package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/alexedwards/argon2id"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/html"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// caseInsensitive matches strings ignoring case and accents (strength 2), so
// email lookups resolve regardless of how the address was typed or stored.
var caseInsensitive = &options.Collation{Locale: "en", Strength: 2}

// normalizeEmail canonicalizes an email address for storage and comparison.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// newStateToken returns an unguessable single-use OAuth state value.
func newStateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// handleRevoke ingests revoked JWTs from NextAuth.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		JTI string `json:"jti"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.JTI == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Insert the UUID into the blocked collection
	_, err := s.revokedTokensCol.InsertOne(r.Context(), bson.M{
		"jti":       payload.JTI,
		"createdAt": time.Now(),
	})
	if err != nil && !mongo.IsDuplicateKeyError(err) {
		slog.Error("failed to save revoked token", "err", err)
	}
	w.WriteHeader(http.StatusOK)
}

// validateEbayKeyset checks a tenant's credentials against eBay before the
// account is created. Registration previously accepted anything, so a typo in
// the App ID or Cert ID produced an account that failed on every page forever,
// with no way to correct it.
func (s *Server) validateEbayKeyset(ctx context.Context, cfg EbayDeveloperConfig) error {
	authURL := ebay.ProdAuthURL
	if cfg.IsSandbox || strings.Contains(cfg.AppID, "SBX-") {
		authURL = ebay.SandboxAuthURL
	}

	client := &auth.Client{
		Client:       s.httpClient,
		DB:           s.ebayAccountsCol,
		AuthURL:      authURL,
		ClientID:     cfg.AppID,
		ClientSecret: cfg.CertID,
		DevID:        cfg.DevID,
	}

	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if _, err := client.GetApplicationToken(checkCtx); err != nil {
		return err
	}
	return nil
}

// handleRegisterUser registers a new Sealift user (called by Next.js frontend).
func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var user SealiftUser
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil || user.Email == "" || user.PasswordHash == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Emails are case-insensitive identifiers: store them normalized so
	// "Foo@x.com" and "foo@x.com" can never become two accounts.
	user.Email = normalizeEmail(user.Email)

	// The unique index is case-sensitive, so it alone won't catch a new
	// lowercase address colliding with an existing mixed-case one.
	existing, err := s.sealiftUsersCol.CountDocuments(r.Context(),
		bson.M{"email": user.Email}, options.Count().SetCollation(caseInsensitive))
	if err != nil {
		slog.Error("failed to check for existing user", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existing > 0 {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	// Reject bad credentials up front rather than creating an account that can
	// never talk to eBay.
	if err := s.validateEbayKeyset(r.Context(), user.EbayDeveloperConfig); err != nil {
		slog.Warn("rejected registration with invalid eBay keyset", "err", err, "email", user.Email)
		http.Error(w,
			"eBay rejected these developer keys. Check the App ID and Cert ID (and the Sandbox setting) and try again.",
			http.StatusBadRequest)
		return
	}

	user.CreatedAt = time.Now()
	result, err := s.sealiftUsersCol.InsertOne(r.Context(), user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}
		slog.Error("failed to create user", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newTenantID := result.InsertedID.(primitive.ObjectID).Hex()
	slog.Info("created new Sealift tenant", "tenantID", newTenantID)

	// Create tenant-level notification destination immediately. If this fails
	// it is not fatal: subscribing later re-creates the destination on demand
	// (see ensureTenantDestination).
	go func(tenantID string) {
		slog.Info("registering tenant-level notification destination", "tenantID", tenantID)
		dynamicClient, _, err := s.getEbayClientForUser(context.Background(), tenantID)
		if err != nil {
			slog.Error("failed to register tenant", "err", err, "tenantID", tenantID)
			return
		}

		if _, err := s.ensureTenantDestination(context.Background(), dynamicClient, tenantID); err != nil {
			slog.Warn("failed to create destination; will retry on first subscribe", "err", err, "tenantID", tenantID)
		}
	}(newTenantID)

	json.NewEncoder(w).Encode(map[string]interface{}{"id": result.InsertedID})
}

// findUserByEmail resolves a tenant case-insensitively, so accounts created
// before emails were normalized (and any odd casing a user types) still match.
func (s *Server) findUserByEmail(ctx context.Context, email string) (SealiftUser, error) {
	var user SealiftUser
	err := s.sealiftUsersCol.FindOne(ctx,
		bson.M{"email": normalizeEmail(email)},
		options.FindOne().SetCollation(caseInsensitive),
	).Decode(&user)
	return user, err
}

// verifyPassword checks a plaintext password against a stored argon2 hash.
// Older records wrapped the PHC string in base64 before storing it.
func verifyPassword(password, storedHash string) (bool, error) {
	if !strings.HasPrefix(storedHash, "$argon2") {
		decoded, err := base64.StdEncoding.DecodeString(storedHash)
		if err != nil {
			return false, fmt.Errorf("stored hash is neither PHC nor base64; %w", err)
		}
		storedHash = string(decoded)
	}
	return argon2id.ComparePasswordAndHash(password, storedHash)
}

// handleVerifyCredentials authenticates a tenant for the frontend's sign-in
// flow. The password hash is verified here and never leaves the backend — this
// replaced an endpoint that returned the whole user document (hash and eBay
// developer keyset included) to anyone who could reach it.
func (s *Server) handleVerifyCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	user, err := s.findUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			slog.Error("credential lookup failed", "err", err)
		}
		// Same response whether the account is missing or the password is
		// wrong, so this can't be used to enumerate accounts.
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	ok, err := verifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		slog.Error("password verification failed", "err", err, "userID", user.ID.Hex())
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if !ok {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Only what the session needs — no hash, no eBay credentials.
	json.NewEncoder(w).Encode(map[string]string{
		"id":    user.ID.Hex(),
		"email": user.Email,
	})
}

// handleRegisterSeller redirects to eBay's OAuth consent page (BYOK Dynamic Route).
func (s *Server) handleRegisterSeller(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok || userID == "" {
		http.Error(w, "Unauthorized Context", http.StatusUnauthorized)
		return
	}

	_, user, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to load Dev Configs", http.StatusInternalServerError)
		return
	}

	var authUrl string
	if user.EbayDeveloperConfig.IsSandbox || strings.Contains(user.EbayDeveloperConfig.AppID, "SBX-") {
		authUrl = ebay.SandboxSignInURL
	} else {
		authUrl = ebay.ProdSignInURL
	}

	// `state` must be unguessable and single-use: it is what the (unauthenticated)
	// callback trusts to decide which tenant a seller gets attached to. Using the
	// tenant ID itself let anyone who guessed an ID bind a seller to that tenant.
	stateToken, err := newStateToken()
	if err != nil {
		slog.Error("failed to generate oauth state", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if _, err := s.oauthStatesCol.InsertOne(r.Context(), bson.M{
		"state":     stateToken,
		"tenantId":  userID,
		"createdAt": time.Now(),
	}); err != nil {
		slog.Error("failed to persist oauth state", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	consentURL := fmt.Sprintf(
		"%s/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&state=%s",
		authUrl,
		user.EbayDeveloperConfig.AppID,
		user.EbayDeveloperConfig.RedirectURI,
		ebayScope,
		stateToken,
	)

	slog.Info("redirecting to oauth consent page", "userId", userID)
	http.Redirect(w, r, consentURL, http.StatusTemporaryRedirect)
}

// handleAuthCallback handles the eBay OAuth callback (BYOK Handshake).
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	slog.Info("TRACE: /api/auth-callback reached", "url", r.URL.String())

	// eBay redirects here on the seller's own domain, so there is usually no
	// session cookie: the single-use state token is what identifies the tenant.
	// Consuming it here also prevents the callback from being replayed.
	stateToken := r.URL.Query().Get("state")
	userID := ""
	if stateToken != "" {
		var stateDoc struct {
			TenantID string `bson:"tenantId"`
		}
		if err := s.oauthStatesCol.FindOneAndDelete(r.Context(),
			bson.M{"state": stateToken}).Decode(&stateDoc); err != nil {
			slog.Error("oauth state not recognized", "err", err)
		} else {
			userID = stateDoc.TenantID
		}
	}

	// Fall back to the session cookie when the callback lands on the frontend
	// domain (e.g. local development through a single tunnel).
	if userID == "" {
		if sessionUser, ok := r.Context().Value("userId").(string); ok {
			userID = sessionUser
		}
	}

	if userID == "" {
		html.RenderAuthError(w, "This authorization link has expired. Please try adding the seller again.", frontendURL)
		return
	}

	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		slog.Error("missing auth code", "query", r.URL.Query().Encode())
		html.RenderAuthError(w, "missing auth code", frontendURL)
		return
	}

	slog.Info("received auth code in callback, resolving dynamic client...")

	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client during auth-callback", "err", err, "userID", userID)
		html.RenderAuthError(w, "database mapping failure", frontendURL)
		return
	}

	ebayUserStore, err := dynamicClient.Auth.AuthUser(r.Context(), authCode, userID)
	if err != nil {
		slog.Error("Failed to auth user/write to mongo", "err", err, "userID", userID)
		html.RenderAuthError(w, "failed to auth user", frontendURL)
		return
	}

	slog.Info("Handshake Complete: seller authorized and written to DB", "ebayUser", ebayUserStore, "tenantID", userID)

	html.RenderAuthSuccess(w, frontendURL, ebayUserStore)
}

// handleDeleteAccount permanently deletes the Sealift tenant and all associated resources.
// Cleanup order: subscriptions → destination → ebay_accounts → inbox → notes → sealift_user
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value("userId").(string)
	if !ok || userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	slog.Info("DELETE ACCOUNT initiated", "tenantID", userID)

	// Build the eBay client for this tenant
	dynamicClient, sealiftUser, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build client for account deletion", "err", err, "tenantID", userID)
		http.Error(w, "Failed to resolve tenant credentials", http.StatusInternalServerError)
		return
	}

	// 1. Get all eBay sellers under this tenant
	sellers, err := dynamicClient.Auth.GetUsers(r.Context(), userID)
	if err != nil {
		slog.Warn("Failed to enumerate sellers during account deletion", "err", err, "tenantID", userID)
	}

	// 2. For each seller: delete all eBay notification subscriptions
	// safe because DeleteAllUserSubscriptions is scoped to the
	// tenant's own eBay API credentials
	// (the subscriptions belong to the tenant's app, not the seller globally).
	// So each tenant's subscriptions are independent even for shared sellers.
	for _, seller := range sellers {
		sellerCtx := context.WithValue(r.Context(), auth.USER, seller)
		if err := dynamicClient.DeleteAllUserSubscriptions(sellerCtx); err != nil {
			slog.Warn("Failed to delete subscriptions for seller", "seller", seller, "err", err)
		} else {
			slog.Info("Deleted all subscriptions for seller", "seller", seller)
		}
	}

	// 3. Disable and delete the tenant's notification destination
	if sealiftUser.DestinationID != "" {
		destinationURL := fmt.Sprintf("%s/tenant/%s", endpointURL, userID)
		if err := dynamicClient.DisableDestination(r.Context(), sealiftUser.DestinationID, destinationURL, verificationToken); err != nil {
			slog.Warn("Failed to disable tenant destination", "destID", sealiftUser.DestinationID, "err", err)
		}
		if err := dynamicClient.DeleteDestination(r.Context(), sealiftUser.DestinationID); err != nil {
			slog.Warn("Failed to delete tenant destination", "destID", sealiftUser.DestinationID, "err", err)
		} else {
			slog.Info("Deleted tenant notification destination", "destID", sealiftUser.DestinationID)
		}
	}

	dbCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// 4. Delete all ebay_accounts for this tenant
	ebayResult, err := s.ebayAccountsCol.DeleteMany(dbCtx, bson.M{"sealift_user_id": userID})
	if err != nil {
		slog.Warn("Failed to delete ebay_accounts", "err", err, "tenantID", userID)
	} else {
		slog.Info("Deleted ebay_accounts", "count", ebayResult.DeletedCount, "tenantID", userID)
	}

	// 5. Delete inbox notifications ONLY for sellers exclusive to this tenant.
	// Two tenants can register the same eBay seller -- inbox docs are keyed by
	// seller username without a tenant scope, so we must not wipe data that
	// another tenant still depends on.
	for _, seller := range sellers {
		otherTenantCount, err := s.ebayAccountsCol.CountDocuments(dbCtx, bson.M{
			"user":            seller,
			"sealift_user_id": bson.M{"$ne": userID},
		})
		if err != nil {
			slog.Warn("Failed to check shared seller ownership", "seller", seller, "err", err)
			continue
		}
		if otherTenantCount > 0 {
			slog.Info("Skipping inbox deletion - seller is shared with another tenant", "seller", seller, "otherTenants", otherTenantCount)
			continue
		}

		inboxResult, err := s.inboxReceiver.DB.DeleteMany(dbCtx, bson.M{"user": seller})
		if err != nil {
			slog.Warn("Failed to delete inbox for seller", "seller", seller, "err", err)
		} else {
			slog.Info("Deleted inbox notifications", "seller", seller, "count", inboxResult.DeletedCount)
		}
	}

	// 6. Delete all notes for this tenant
	notesResult, err := s.notesCol.DeleteMany(dbCtx, bson.M{"sealift_user_id": userID})
	if err != nil {
		slog.Warn("Failed to delete notes", "err", err, "tenantID", userID)
	} else {
		slog.Info("Deleted notes", "count", notesResult.DeletedCount, "tenantID", userID)
	}

	// 7. Delete the sealift_users document itself
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		slog.Error("Invalid tenant ObjectID during account deletion", "err", err, "tenantID", userID)
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		return
	}
	userResult, err := s.sealiftUsersCol.DeleteOne(dbCtx, bson.M{"_id": objID})
	if err != nil {
		slog.Error("Failed to delete sealift_user", "err", err, "tenantID", userID)
		http.Error(w, "Failed to delete account", http.StatusInternalServerError)
		return
	}
	if userResult.DeletedCount == 0 {
		slog.Error("sealift_user not found for deletion", "tenantID", userID)
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	slog.Info("DELETE ACCOUNT completed", "tenantID", userID, "sellersRemoved", len(sellers))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "deleted",
		"sellers_removed": len(sellers),
	})
}
