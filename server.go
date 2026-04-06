package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/inbox"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type Server struct {
	mux                   *http.ServeMux
	httpClient            *http.Client
	db                    *mongo.Database
	sealiftUsersCol       *mongo.Collection
	notesCol              *mongo.Collection
	ebayAccountsCol       *mongo.Collection // eBay specific
	inboxReceiver         *inbox.Receiver
	revokedTokensCol      *mongo.Collection
	knowledgeBaseLocalCol *mongo.Collection
	knowledgeBaseAtlasCol *mongo.Collection
}

// getEbayClientForUser builds an eBay client
// scoped to a specific Sealift tenant.
func (s *Server) getEbayClientForUser(
	reqCtx context.Context,
	strictUserID string,
) (*ebay.Client, SealiftUser, error) {
	var user SealiftUser
	objID, err := primitive.ObjectIDFromHex(strictUserID)
	if err != nil {
		return nil, user, fmt.Errorf("failed to parse user ID: %w", err)
	}
	if err := s.sealiftUsersCol.FindOne(reqCtx, bson.M{"_id": objID}).Decode(&user); err != nil {
		return nil, user, fmt.Errorf("failed to find user: %w", err)
	}

	u := ebay.ProdAPIURL
	tu := ebay.ProdTradURL
	nu := ebay.ProdNotificationURL
	au := ebay.ProdAuthURL
	uu := ebay.ProdIdentityURL

	if user.EbayDeveloperConfig.IsSandbox || strings.Contains(user.EbayDeveloperConfig.AppID, "SBX-") {
		u = ebay.SandboxAPIURL
		tu = ebay.SandboxTradURL
		nu = ebay.SandboxNotificationURL
		au = ebay.SandboxAuthURL
		uu = ebay.SandboxIdentityURL
	}

	return &ebay.Client{
		Client:          s.httpClient,
		URL:             u,
		TradURL:         tu,
		NotificationURL: nu,
		Auth: &auth.Client{
			Client:       s.httpClient,
			DB:           s.ebayAccountsCol,
			AuthURL:      au,
			RedirectURI:  user.EbayDeveloperConfig.RedirectURI,
			ClientID:     user.EbayDeveloperConfig.AppID,
			ClientSecret: user.EbayDeveloperConfig.CertID,
			DevID:        user.EbayDeveloperConfig.DevID,
			UserAPI:      uu,
		},
	}, user, nil
}

// getAnyEbayClient builds a dynamic eBay client from the first available
// Sealift tenant. Used for app-level API calls (e.g. GetPublicKey) where
// no specific tenant ID is available, like the deletion webhook.
func (s *Server) getAnyEbayClient(ctx context.Context) (*ebay.Client, error) {
	// 1. Try global environment variables first (most robust for app-level webhooks)
	if ebayAppID != "" && ebayCertID != "" {
		u, tu, nu, au, uu := ebay.ProdAPIURL, ebay.ProdTradURL, ebay.ProdNotificationURL, ebay.ProdAuthURL, ebay.ProdIdentityURL
		if strings.Contains(ebayAppID, "SBX-") {
			u, tu, nu, au, uu = ebay.SandboxAPIURL, ebay.SandboxTradURL, ebay.SandboxNotificationURL, ebay.SandboxAuthURL, ebay.SandboxIdentityURL
		}

		return &ebay.Client{
			Client:          s.httpClient,
			URL:             u,
			TradURL:         tu,
			NotificationURL: nu,
			Auth: &auth.Client{
				Client:       s.httpClient,
				DB:           s.ebayAccountsCol,
				AuthURL:      au,
				ClientID:     ebayAppID,
				ClientSecret: ebayCertID,
				DevID:        ebayDevID,
				UserAPI:      uu,
			},
		}, nil
	}

	// 2. Fallback to borrowing from the first available tenant in DB
	var user SealiftUser
	err := s.sealiftUsersCol.FindOne(ctx, bson.M{}).Decode(&user)
	if err != nil {
		return nil, fmt.Errorf("no tenants or ENV credentials available: %w", err)
	}

	client, _, err := s.getEbayClientForUser(ctx, user.ID.Hex())
	if err != nil {
		return nil, fmt.Errorf("failed to build client from tenant: %w", err)
	}
	return client, nil
}

// registerRoutes wires all HTTP routes to their handler methods.
func (s *Server) registerRoutes() {
	// Catch-all
	s.mux.HandleFunc("/", s.handleRoot)

	// Auth
	s.mux.HandleFunc("/api/revoke", s.handleRevoke)
	s.mux.HandleFunc("/api/register-user", s.handleRegisterUser)
	s.mux.HandleFunc("/api/internal/get-user", s.handleGetUser) // server-to-server (call originates from NextJS Auth)
	s.mux.HandleFunc("/api/register-seller", s.handleRegisterSeller)
	s.mux.HandleFunc("/api/auth-callback", s.handleAuthCallback)
	s.mux.HandleFunc("DELETE /api/delete-account", s.handleDeleteAccount)

	// eBay
	s.mux.HandleFunc("GET /api/users", s.handleGetUsers)
	s.mux.HandleFunc("DELETE /api/users/{user}", s.handleDeleteUser)
	s.mux.HandleFunc("GET /api/transaction-summaries", s.handleGetTransactionSummaries)
	s.mux.HandleFunc("GET /api/payouts/{user}", s.handleGetPayouts)
	s.mux.HandleFunc("GET /api/listings/{user}", s.handleGetListings)
	s.mux.HandleFunc("GET /api/account/{user}", s.handleGetAccount)

	// Notes
	s.mux.HandleFunc("GET /api/notes", s.handleGetNotes)
	s.mux.HandleFunc("POST /api/notes", s.handleCreateNote)
	s.mux.HandleFunc("PUT /api/notes/{id}", s.handleUpdateNote)
	s.mux.HandleFunc("DELETE /api/notes/{id}", s.handleDeleteNote)

	// Notifications
	s.mux.HandleFunc("GET /api/notification/topic/{topicId}", s.handleGetTopic)
	s.mux.HandleFunc("GET /api/notification/topics", s.handleGetTopics)
	s.mux.HandleFunc("GET /api/notification/destinations", s.handleGetDestinations)
	s.mux.HandleFunc("DELETE /api/notification/destinations", s.handleDeleteTenantDestination)
	s.mux.HandleFunc("POST /api/notification/users/{user}/subscriptions", s.handleCreateSubscription)
	s.mux.HandleFunc("GET /api/notification/users/{user}/subscriptions", s.handleGetSubscriptions)
	s.mux.HandleFunc("DELETE /api/notification/users/{user}/subscriptions", s.handleDeleteSubscriptions)
	s.mux.HandleFunc("POST /api/notification/users/{user}/subscriptions/enable", s.handleEnableSubscriptions)
	s.mux.HandleFunc("POST /api/notification/users/{user}/subscriptions/{subscriptionId}/test", s.handleTestSubscription)

	// Webhooks
	s.mux.HandleFunc("/sealift-webhook", s.handleDeletionWebhook)
	s.mux.HandleFunc("/sealift-webhook/tenant/{tenantID}", s.handleNotificationWebhook)

	// Inbox
	s.mux.HandleFunc("PUT /api/inbox/{user}/{notificationId}/trash", s.handleTrashNotification)
	s.mux.HandleFunc("PUT /api/inbox/{user}/{notificationId}/mark_read", s.handleMarkRead)
	s.mux.HandleFunc("DELETE /api/inbox/{user}/{notificationId}/trash", s.handleDeletePermanent)

	// SSE
	s.mux.HandleFunc("GET /api/notifications/{user}/stream", s.handleSSEStream)

	// AI
	s.mux.HandleFunc("POST /api/ai/ingest", s.handleAIIngest)
	s.mux.HandleFunc("GET /api/ai/ask", s.handleAIAsk)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	slog.Info("received request at /", "path", r.URL.Path)
	http.Error(w, "Not Found", http.StatusNotFound)
}
