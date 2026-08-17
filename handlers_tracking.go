package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"golang.org/x/sync/errgroup"

	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/usps"
)

type TrackingUserOrders struct {
	User   string       `json:"user"`
	Orders []ebay.Order `json:"orders"`
}

func (s *Server) handleTracking(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok || userID == "" {
		slog.Error("userId missing from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	slog.Info("received request", "path", r.URL.Path, "userId", userID)

	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for tracking", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	users, err := dynamicClient.Auth.GetUsers(r.Context(), userID)
	if err != nil {
		slog.Error("failed to get registered users", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allOrders := make([]TrackingUserOrders, len(users))
	g, ctx := errgroup.WithContext(r.Context())

	var failedUser string
	var mu sync.Mutex

	for i, user := range users {
		i, user := i, user
		g.Go(func() error {
			userCtx := context.WithValue(ctx, auth.USER, user)
			resp, err := dynamicClient.GetOrders(userCtx)
			if err != nil {
				mu.Lock()
				if failedUser == "" {
					failedUser = user
				}
				mu.Unlock()
				return err
			}

			allOrders[i] = TrackingUserOrders{
				User:   user,
				Orders: resp.Orders,
			}
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		if respondIfReauthRequired(w, err, failedUser) {
			return
		}
		slog.Error("failed to get orders", "err", err, "user", failedUser)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allOrders)
}

func (s *Server) handleUSPSTracking(w http.ResponseWriter, r *http.Request) {
	if s.usps == nil {
		http.Error(w, "USPS is not configured", http.StatusServiceUnavailable)
		return
	}

	number := strings.TrimSpace(r.PathValue("trackingNumber"))
	if number == "" {
		http.Error(w, "trackingNumber required", http.StatusBadRequest)
		return
	}

	track, err := s.usps.Track(r.Context(), usps.TrackRequest{
		TrackingNumber:     number,
		MailingDate:        usps.MailingDate(r.URL.Query().Get("mailingDate")),
		DestinationZIPCode: usps.DestinationZIP(r.URL.Query().Get("destinationZIPCode")),
	})
	if err != nil {
		slog.Warn("USPS tracking lookup failed", "trackingNumber", number, "err", err)
		status := http.StatusServiceUnavailable
		var apiErr *usps.APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusBadRequest) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(track)
}
