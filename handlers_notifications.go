package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.tesla.com/chrzhang/sealift/api"
	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
)

func (s *Server) handleGetTopic(w http.ResponseWriter, r *http.Request) {
	topicID := r.PathValue("topicId")
	if strings.TrimSpace(topicID) == "" {
		slog.Error("topic ID not specified")
		http.Error(w, "topic ID not specified", http.StatusBadRequest)
		return
	}

	slog.Info("received request for notification topic", "topicId", topicID)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for get topic", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	topic, err := dynamicClient.GetTopic(r.Context(), topicID)
	if err != nil {
		slog.Error("failed to get notification topic", "err", err, "topicId", topicID)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.NotificationTopic{Topic: topic})
}

func (s *Server) handleGetTopics(w http.ResponseWriter, r *http.Request) {
	slog.Info("received request for all notification topics")

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for get topics", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	topics, err := dynamicClient.GetTopics(r.Context())
	if err != nil {
		slog.Error("failed to get notification topics", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.NotificationTopics{Topics: topics})
}

// handleGetDestinations gets notification destinations (debug only).
func (s *Server) handleGetDestinations(w http.ResponseWriter, r *http.Request) {
	defaultPageSize := 100
	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil {
		slog.Info("missing page size; using default value", "pageSize", defaultPageSize)
		pageSize = defaultPageSize
	}

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for destinations list", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	dests, err := dynamicClient.GetDestinations(r.Context(), pageSize)
	if err != nil {
		slog.Error("failed to get destinations", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Group destinations by user (using the Name field)
	userDestMap := make(map[string][]ebay.Destination)
	for _, d := range dests.Destinations {
		user := d.Name
		userDestMap[user] = append(userDestMap[user], d)
	}

	var userDestinations []api.UserDestination
	for user, userDests := range userDestMap {
		userDestinations = append(userDestinations, api.UserDestination{
			User:         user,
			Destinations: userDests,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.NotificationDestinations{
		UserDestinations: userDestinations,
		Next:             dests.Next,
		Total:            dests.Total,
	})
}

// handleDeleteTenantDestination deletes the tenant's single notification destination.
// Useful for resetting the webhook destination if the ngrok URL changes or something gets misconfigured.
func (s *Server) handleDeleteTenantDestination(w http.ResponseWriter, r *http.Request) {
	slog.Info("received request to delete the tenant's destination")
	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for destination delete", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	pageSize := 100
	dests, err := dynamicClient.GetDestinations(r.Context(), pageSize)
	if err != nil {
		slog.Error("failed to get destinations", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deletedCount := 0
	errCount := 0
	for _, d := range dests.Destinations {
		// Under BYOK, the destination's Name is set identically to the tenant's userID
		if d.Name == userID {
			if err := dynamicClient.DisableDestination(r.Context(), d.DestinationID, d.DeliveryConfig.Endpoint, verificationToken); err != nil {
				slog.Error("failed to disable tenant destination", "destinationId", d.DestinationID, "err", err)
			}

			if err := dynamicClient.DeleteDestination(r.Context(), d.DestinationID); err != nil {
				slog.Error("failed to delete tenant destination", "destinationId", d.DestinationID, "err", err)
				errCount++
			} else {
				deletedCount++
			}
		}
	}

	resp := map[string]interface{}{
		"deleted_count": deletedCount,
		"error_count":   errCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleCreateSubscription creates a notification subscription for a seller.
func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified", http.StatusBadRequest)
		return
	}

	var req struct {
		TopicID string `json:"topicId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("invalid request body", "err", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.TopicID == "" {
		http.Error(w, "topicId is required", http.StatusBadRequest)
		return
	}

	slog.Info("received request to create notification subscription", "user", user, "topicId", req.TopicID)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, sealiftUser, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for subscription create", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	subID, err := dynamicClient.CreateUserSubscription(userCtx, req.TopicID, sealiftUser.DestinationID)
	if err != nil {
		slog.Error("failed to create subscription", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(api.CreateUserSubscription{SubscriptionID: subID})
}

// handleGetSubscriptions gets subscriptions for a seller.
func (s *Server) handleGetSubscriptions(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified", http.StatusBadRequest)
		return
	}

	slog.Info("received request for notification subscriptions", "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for subscriptions list", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	subs, err := dynamicClient.GetUserSubscriptions(userCtx)
	if err != nil {
		slog.Error("failed to get subscriptions", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.NotificationSubscriptions{Subscriptions: subs})
}

// handleDeleteSubscriptions deletes ALL subscriptions for a seller.
func (s *Server) handleDeleteSubscriptions(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified", http.StatusBadRequest)
		return
	}

	slog.Info("received request to delete all notification subscriptions", "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for subscriptions delete", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	if err := dynamicClient.DeleteAllUserSubscriptions(userCtx); err != nil {
		slog.Error("failed to delete subscriptions", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleEnableSubscriptions enables subscriptions for a seller.
func (s *Server) handleEnableSubscriptions(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified", http.StatusBadRequest)
		return
	}

	slog.Info("received request to enable subscriptions", "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for subscriptions enable", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	subs, err := dynamicClient.EnableUserSubscriptions(userCtx)
	if err != nil {
		slog.Error("failed to enable subscriptions", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.NotificationSubscriptions{Subscriptions: subs})
}

// handleTestSubscription tests a subscription for a seller.
func (s *Server) handleTestSubscription(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	subscriptionID := r.PathValue("subscriptionId")
	if user == "" || subscriptionID == "" {
		http.Error(w, "user and subscription ID required", http.StatusBadRequest)
		return
	}

	slog.Info("received request to test subscription", "user", user, "subscriptionId", subscriptionID)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for test subscription", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	err = dynamicClient.TestUserSubscription(userCtx, subscriptionID)
	if err != nil {
		slog.Error("failed to test subscription", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("triggered test payload for subscription", "subscriptionId", subscriptionID, "user", user)

	w.WriteHeader(http.StatusNoContent)
}

// handleNotificationWebhook handles webhooks for all seller notifications under a Sealift Tenant.
func (s *Server) handleNotificationWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantID")
	if tenantID == "" {
		http.Error(w, "tenant not specified", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// eBay verification challenge
		challengeCode := r.URL.Query().Get("challenge_code")
		if challengeCode != "" {
			hashInput := challengeCode + verificationToken + endpointURL + "/tenant/" + tenantID
			hash := sha256.Sum256([]byte(hashInput))
			hashString := fmt.Sprintf("%x", hash)
			resp := ChallengeResponse{ChallengeResponse: hashString}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)

	case http.MethodPost:
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// Get tenant's cryptographic keys to verify signature
		client, _, err := s.getEbayClientForUser(r.Context(), tenantID)
		if err != nil {
			slog.Error("Webhook failed: Tenant client not found", "tenantID", tenantID)
			http.Error(w, "Unauthorized Tenant", http.StatusUnauthorized)
			return
		}

		if err := verifyEbaySignature(r, reqBody, client); err != nil {
			slog.Error("Webhook signature validation failed", "err", err, "tenantID", tenantID)
			http.Error(w, "Invalid Signature", http.StatusPreconditionFailed)
			return
		}

		var payload ebay.NotificationPayload
		if err := json.Unmarshal(reqBody, &payload); err != nil {
			slog.Error("failed to decode payload", "err", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Route to the correct eBay store's inbox
		ebayUser := payload.Notification.Data.SenderUserName
		if ebayUser == "" {
			slog.Error("Webhook error: missing sender username in payload")
			http.Error(w, "Missing Sender", http.StatusBadRequest)
			return
		}

		var notif map[string]interface{}
		json.Unmarshal(reqBody, &notif)
		s.inboxReceiver.PushNotification(r.Context(), ebayUser, notif)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeletionWebhook handles the required webhook for deletion events.
func (s *Server) handleDeletionWebhook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// handle verification challenge
		challengeCode := r.URL.Query().Get("challenge_code")
		if challengeCode == "" {
			http.Error(w, "missing challenge code", http.StatusBadRequest)
			return
		}

		// compute hash for challenge code + verification token + endpoint URL
		hashInput := challengeCode + verificationToken + endpointURL
		hash := sha256.Sum256([]byte(hashInput))
		hashString := fmt.Sprintf("%x", hash)

		slog.Info("computed hash for challenge code", "url", endpointURL)

		resp := ChallengeResponse{ChallengeResponse: hashString}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "invalid challenge resp", http.StatusBadRequest)
			return
		}

	case http.MethodPost:
		// read raw body for signature verification
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// actively check for webhook spoofing!
		// Use any available tenant's credentials for the app-level GetPublicKey call
		// since the deletion webhook has no tenant ID.
		client, err := s.getAnyEbayClient(r.Context())
		if err != nil {
			slog.Error("No tenant credentials available for signature verification", "err", err)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := verifyEbaySignature(r, reqBody, client); err != nil {
			slog.Error("Webhook signature validation failed", "err", err, "path", r.URL.Path)
			http.Error(w, "Precondition Failed: Invalid Signature", http.StatusPreconditionFailed)
			return
		}

		// handle deletion notification
		var notif map[string]interface{}
		if err := json.Unmarshal(reqBody, &notif); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		slog.Info("received verification-passed deletion notification", "notif", notif)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- eBay Signature Verification ---

var (
	ebayKeyCache = make(map[string]interface{})
	ebayKeyMutex sync.RWMutex
)

// verifyEbaySignature actively checks the X-Ebay-Signature header to ensure webhooks originated from eBay.
func verifyEbaySignature(r *http.Request, reqBody []byte, client *ebay.Client) error {
	signatureHeader := r.Header.Get("X-Ebay-Signature")
	if signatureHeader == "" {
		return errors.New("missing X-Ebay-Signature header")
	}

	decodedHeader, err := base64.StdEncoding.DecodeString(signatureHeader)
	if err != nil {
		return fmt.Errorf("invalid base64 signature header: %v", err)
	}

	var sigData struct {
		Alg       string `json:"alg"`
		Kid       string `json:"kid"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(decodedHeader, &sigData); err != nil {
		return fmt.Errorf("failed to parse signature JSON: %v", err)
	}

	if sigData.Kid == "" || sigData.Signature == "" {
		return errors.New("missing kid or signature in X-Ebay-Signature")
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(sigData.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature payload: %v", err)
	}

	// 1. Check Memory Cache for Public Key
	ebayKeyMutex.RLock()
	pubKey, exists := ebayKeyCache[sigData.Kid]
	ebayKeyMutex.RUnlock()

	// 2. Get Public Key if missing
	if !exists {
		// Use empty context without User context because public keys are an App-level endpoint.
		pubKeyResp, err := client.GetPublicKey(context.Background(), sigData.Kid)
		if err != nil {
			return fmt.Errorf("failed to get public key %s from ebay: %v", sigData.Kid, err)
		}

		block, _ := pem.Decode([]byte(pubKeyResp.Key))
		if block == nil {
			return errors.New("failed to decode PEM block containing public key")
		}

		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}

		// Cache it
		ebayKeyMutex.Lock()
		ebayKeyCache[sigData.Kid] = parsedKey
		pubKey = parsedKey
		ebayKeyMutex.Unlock()
		slog.Info("Successfully cached new eBay Public Key", "kid", sigData.Kid)
	}

	// 3. Cryptographically Verify Signature
	// eBay supports ECDSA, ED25519, and RSA
	switch pub := pubKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, reqBody, decodedSignature) {
			return errors.New("Ed25519 signature verification failed")
		}
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(reqBody)
		if !ecdsa.VerifyASN1(pub, hash[:], decodedSignature) {
			return errors.New("ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		hash := sha256.Sum256(reqBody)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], decodedSignature); err != nil {
			return fmt.Errorf("RSA signature verification failed: %v", err)
		}
	default:
		return fmt.Errorf("unknown key type in cache for kid %s", sigData.Kid)
	}

	return nil
}
