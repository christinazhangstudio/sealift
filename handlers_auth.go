package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
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
		slog.Error("Failed to create user", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	newTenantID := result.InsertedID.(primitive.ObjectID).Hex()
	slog.Info("Created new Sealift tenant", "tenantID", newTenantID)

	// Create tenant-level notification destination immediately
	go func(tenantID string) {
		slog.Info("Registering tenant-level notification destination", "tenantID", tenantID)
		dynamicClient, _, err := s.getEbayClientForUser(context.Background(), tenantID)
		if err != nil {
			slog.Error("Registration background task failed: client-init", "err", err, "tenantID", tenantID)
			return
		}

		// We use the tenantID as the "name" for the destination for easier tracking
		destCtx := context.WithValue(context.Background(), auth.USER, tenantID)
		destinationURL := fmt.Sprintf("%s/tenant/%s", endpointURL, tenantID)

		destID, err := dynamicClient.CreateDestination(destCtx, destinationURL, verificationToken)
		if err != nil {
			slog.Warn("Registration background task warning: destination already exists or failed", "err", err, "url", destinationURL)
		} else {
			slog.Info("Successfully created tenant notification destination", "tenantID", tenantID, "destID", destID)
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

	baseAuthURL := "https://auth.ebay.com/oauth2/authorize?response_type=code&scope=https://api.ebay.com/oauth/api_scope https://api.ebay.com/oauth/api_scope/sell.marketing.readonly https://api.ebay.com/oauth/api_scope/sell.marketing https://api.ebay.com/oauth/api_scope/sell.inventory.readonly https://api.ebay.com/oauth/api_scope/sell.inventory https://api.ebay.com/oauth/api_scope/sell.account.readonly https://api.ebay.com/oauth/api_scope/sell.account https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly https://api.ebay.com/oauth/api_scope/sell.fulfillment https://api.ebay.com/oauth/api_scope/sell.analytics.readonly https://api.ebay.com/oauth/api_scope/sell.finances https://api.ebay.com/oauth/api_scope/sell.payment.dispute https://api.ebay.com/oauth/api_scope/commerce.identity.readonly https://api.ebay.com/oauth/api_scope/sell.reputation https://api.ebay.com/oauth/api_scope/sell.reputation.readonly https://api.ebay.com/oauth/api_scope/commerce.notification.subscription https://api.ebay.com/oauth/api_scope/commerce.notification.subscription.readonly https://api.ebay.com/oauth/api_scope/sell.stores https://api.ebay.com/oauth/api_scope/sell.stores.readonly https://api.ebay.com/oauth/scope/sell.edelivery https://api.ebay.com/oauth/api_scope/commerce.message"
	consentURL := fmt.Sprintf("%s&client_id=%s&redirect_uri=%s&state=%s", baseAuthURL, user.EbayDeveloperConfig.AppID, user.EbayDeveloperConfig.RedirectURI, userID)

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
