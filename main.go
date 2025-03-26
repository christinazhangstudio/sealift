package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
)

var (
	verificationToken   = os.Getenv("VERIFICATION_TOKEN")
	endpointURL         = os.Getenv("ENDPOINT_URL") // for notifications
	clientID            = os.Getenv("EBAY_CLIENT_ID")
	clientSecret        = os.Getenv("EBAY_CLIENT_SECRET")
	ebayURL             = os.Getenv("EBAY_URL")
	ebayAuthURL         = os.Getenv("EBAY_AUTH_URL")
	ebayAuthRedirectURI = os.Getenv("EBAY_AUTH_REDIRECT_URI")
	port                = os.Getenv("PORT")
)

// ChallengeResponse for the verification response.
type ChallengeResponse struct {
	ChallengeResponse string `json:"challengeResponse"`
}

func main() {
	if verificationToken == "" || endpointURL == "" {
		slog.Error("verification token and/or URL must be set")
		return
	}

	ctx := context.Background()

	// client to make HTTP requests to eBay APIs.
	client := &ebay.Client{
		Client: &http.Client{Timeout: time.Second * 5},
		URL:    ebayURL,
		Auth: &auth.Client{
			AuthURL:      ebayAuthURL,
			RedirectURI:  ebayAuthRedirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request at /", "path", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	http.HandleFunc("/sealift-webhook", notificationHandler)

	// on-behalf flow for user token
	http.HandleFunc("/auth-callback", func(w http.ResponseWriter, r *http.Request) {
		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			http.Error(w, "missing auth code", http.StatusBadRequest)
			return
		}

		slog.Info("received auth code in callback")

		fmt.Fprintf(w, "token stored for seller")
	})

	http.HandleFunc("/get-transaction-summary", func(w http.ResponseWriter, r *http.Request) {
		for user := range client.Auth.GetUsers() {
			ctx = context.WithValue(context.Background(), auth.USER, user)
			err := client.GetTransactionSummary(ctx)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})

	slog.Info("starting server", "port", port)

	err := http.ListenAndServe(port, nil)
	if err != nil {
		slog.Error("server failed", "err", err)
	}

	slog.Info("server stopped!")
}

func notificationHandler(w http.ResponseWriter, r *http.Request) {
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
		// handle deletion notification
		var notif map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&notif); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		slog.Info("received deletion notification", "notif", notif)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
