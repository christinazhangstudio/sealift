package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
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

	var allOrders []TrackingUserOrders
	for _, user := range users {
		userCtx := context.WithValue(r.Context(), auth.USER, user)
		resp, err := dynamicClient.GetOrders(userCtx)
		if err != nil {
			if respondIfReauthRequired(w, err, user) {
				return
			}
			slog.Error("failed to get orders", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		allOrders = append(allOrders, TrackingUserOrders{
			User:   user,
			Orders: resp.Orders,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allOrders)
}
