package main

import (
	"context"
	"encoding/json"
	"fmt"
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
)

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

	// Create tenant-level notification destination immediately
	go func(tenantID string) {
		slog.Info("registering tenant-level notification destination", "tenantID", tenantID)
		dynamicClient, _, err := s.getEbayClientForUser(context.Background(), tenantID)
		if err != nil {
			slog.Error("failed to register tenant", "err", err, "tenantID", tenantID)
			return
		}

		// We use the tenantID as the "name" for the destination for easier tracking
		destCtx := context.WithValue(context.Background(), auth.USER, tenantID)
		destinationURL := fmt.Sprintf("%s/tenant/%s", endpointURL, tenantID)

		destID, err := dynamicClient.CreateDestination(destCtx, destinationURL, verificationToken)
		if err != nil {
			slog.Warn("failed to create destination", "err", err, "url", destinationURL)
		} else {
			slog.Info("successfully created tenant notification destination", "tenantID", tenantID, "destID", destID)
			// Store the destination ID on the tenant record
			objID, _ := primitive.ObjectIDFromHex(tenantID)
			s.sealiftUsersCol.UpdateOne(context.Background(), bson.M{"_id": objID}, bson.M{"$set": bson.M{"destinationID": destID}})
		}
	}(newTenantID)

	json.NewEncoder(w).Encode(map[string]interface{}{"id": result.InsertedID})
}

// handleGetUser gets a user by email for NextAuth login verification.
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	// Only allow local calls in production context. Skipping auth middleware as it's internal.
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Email required", http.StatusBadRequest)
		return
	}
	var user SealiftUser
	if err := s.sealiftUsersCol.FindOne(r.Context(), bson.M{"email": email}).Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(user)
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

	consentURL := fmt.Sprintf(
		"%s/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=%s&state=%s",
		authUrl,
		user.EbayDeveloperConfig.AppID,
		user.EbayDeveloperConfig.RedirectURI,
		ebayScope,
		userID,
	)

	slog.Info("redirecting to oauth consent page", "userId", userID)
	http.Redirect(w, r, consentURL, http.StatusTemporaryRedirect)
}

// handleAuthCallback handles the eBay OAuth callback (BYOK Handshake).
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	slog.Info("TRACE: /api/auth-callback reached", "url", r.URL.String())
	userID, ok := r.Context().Value("userId").(string)
	if !ok || userID == "" {
		// Fallback to 'state' parameter for cross-domain tunnels (localhost vs ngrok)
		userID = r.URL.Query().Get("state")
	}

	if userID == "" {
		html.RenderAuthError(w, "Unauthorized session", frontendURL)
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

	html.RenderAuthSuccess(w, frontendURL)
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
