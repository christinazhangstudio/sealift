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

	"github.tesla.com/chrzhang/sealift/ebay"
)

var (
	verificationToken = os.Getenv("VERIFICATION_TOKEN")
	endpointURL       = os.Getenv("ENDPOINT_URL")
	appId             = os.Getenv("EBAY_APP_ID")
	certPath          = "/root/cert/sealift.crt"
	keyPath           = "/root/cert/sealift.key"
	port              = os.Getenv("PORT")
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

	// make eBay client
	client := &ebay.Client{
		Client: &http.Client{Timeout: time.Second * 5},
		AppID:  appId,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request at /", "path", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	http.HandleFunc("/sealift-webhook", notificationHandler)

	http.HandleFunc("/get-transaction-summary", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request at /get-transaction-summary", "path", r.URL.Path)
		client.GetTransactionSummary(ctx)
	})

	slog.Info("starting server", "port", port)

	err := http.ListenAndServeTLS(port, certPath, keyPath, nil)
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
