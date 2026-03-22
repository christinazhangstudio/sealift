package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.tesla.com/chrzhang/sealift/api"
	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func (s *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	slog.Info("received request", "path", r.URL.Path, "userId", userID)

	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for get users", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	users, err := dynamicClient.Auth.GetUsers(r.Context(), userID)
	if err != nil {
		slog.Error("failed to get registered users", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(api.Users{Users: users})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified.", http.StatusBadRequest)
		return
	}

	slog.Info("received request", "path", r.URL.Path, "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for user delete", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	filter := bson.M{
		"user":            user,
		"sealift_user_id": userID,
	}

	// Find user first to get destination ID
	var userDoc struct {
		DestinationID string `bson:"destination_id"`
	}
	err = s.ebayAccountsCol.FindOne(dbCtx, filter).Decode(&userDoc)
	if err == mongo.ErrNoDocuments {
		slog.Error("user not found", "err", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("failed to find user", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete user subscriptions first
	ctxWithUser := context.WithValue(r.Context(), auth.USER, user)
	if err := dynamicClient.DeleteAllUserSubscriptions(ctxWithUser); err != nil {
		slog.Error("failed to delete all user subscriptions", "err", err, "user", user)
	} else {
		slog.Info("deleted all user subscriptions", "user", user)
	}

	result, err := s.ebayAccountsCol.DeleteOne(dbCtx, filter)
	if err != nil {
		slog.Error("failed to delete user", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result.DeletedCount == 0 {
		slog.Error("no user was deleted")
		http.Error(w, "no user was deleted", http.StatusNotFound)
		return
	}

	slog.Info("deleted user", "user", user)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleGetTransactionSummaries gets transaction summaries for all users.
func (s *Server) handleGetTransactionSummaries(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	slog.Info("received request", "path", r.URL.Path, "userId", userID)

	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for transaction summaries", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	users, err := dynamicClient.Auth.GetUsers(r.Context(), userID)
	if err != nil {
		slog.Error("failed to get registered users", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var userSummaries []api.UserSummary
	for _, user := range users {
		userCtx := context.WithValue(r.Context(), auth.USER, user)
		summary, err := dynamicClient.GetTransactionSummary(userCtx)
		if err != nil {
			slog.Error("failed to get transaction summary", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userSummaries = append(userSummaries, api.UserSummary{
			User:    user,
			Summary: summary,
		})
	}

	json.NewEncoder(w).Encode(userSummaries)
}

func (s *Server) handleGetPayouts(w http.ResponseWriter, r *http.Request) {
	defaultPageSize := 200 // maximum allowed by ebay, actual default is 20

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil {
		slog.Info("missing page size; using default value", "pageSize", defaultPageSize)
		pageSize = defaultPageSize
	}

	pageIdx, err := strconv.Atoi(r.URL.Query().Get("pageIdx"))
	if err != nil {
		slog.Info("missing page index; using 0")
		pageIdx = 0
	}

	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified.", http.StatusBadRequest)
		return
	}

	slog.Info("received request", "path", r.URL.Path, "pageSize", pageSize, "pageIdx", pageIdx, "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for payouts", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	payouts, err := dynamicClient.GetPayouts(userCtx, pageSize, pageIdx)
	if err != nil {
		slog.Error("failed to get payouts", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(api.UserPayouts{
		User:    user,
		Payouts: payouts,
	})
}

func (s *Server) handleGetListings(w http.ResponseWriter, r *http.Request) {
	defaultPageSize := 200 // maximum allowed by ebay, actual default is 25

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil {
		slog.Info("missing page size; using default value", "pageSize", defaultPageSize)
		pageSize = defaultPageSize
	}

	pageIdx, err := strconv.Atoi(r.URL.Query().Get("pageIdx"))
	if err != nil {
		slog.Info("missing page index; using 0")
		pageIdx = 1
	}

	layout := "2006-01-02" // YYYY-MM-DD
	startFrom, err := time.Parse(layout, r.URL.Query().Get("startFrom"))
	if err != nil {
		http.Error(w, "invalid startFrom format. Use YYYY-MM-DD.", http.StatusBadRequest)
		return
	}

	startTo, err := time.Parse(layout, r.URL.Query().Get("startTo"))
	if err != nil {
		http.Error(w, "invalid startTo format. Use YYYY-MM-DD.", http.StatusBadRequest)
		return
	}

	if startTo.Before(startFrom) {
		http.Error(w, "startTo must be greater than startFrom.", http.StatusBadRequest)
		return
	}

	daysDiff := startTo.Sub(startFrom).Hours() / 24
	if daysDiff > 120 {
		http.Error(w, "range cannot exceed 120 days.", http.StatusBadRequest)
		return
	}

	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified.", http.StatusBadRequest)
		return
	}

	slog.Info("received request", "path", r.URL.Path, "pageSize", pageSize, "pageIdx", pageIdx, "startFrom", startFrom, "startTo", startTo, "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for listings", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	listings, err := dynamicClient.GetSellerList(userCtx, pageSize, pageIdx, startFrom, startTo)
	// if the error was that no items were found for the seller
	// for the specified range/page index, that's fine
	// use an empty Listings array for the response.
	if err != nil && err != ebay.ErrHasNoMoreItems {
		slog.Error("failed to get listings", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(api.UserListings{
		User:     user,
		Listings: listings,
	})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	defaultPageSize := 200 // maximum allowed by ebay, actual default is 25

	pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil {
		slog.Info("missing page size; using default value", "pageSize", defaultPageSize)
		pageSize = defaultPageSize
	}

	pageIdx, err := strconv.Atoi(r.URL.Query().Get("pageIdx"))
	if err != nil {
		slog.Info("missing page index; using 1")
		pageIdx = 1
	}

	user := r.PathValue("user")
	if user == "" {
		http.Error(w, "user not specified.", http.StatusBadRequest)
		return
	}

	slog.Info("received request", "path", r.URL.Path, "pageSize", pageSize, "pageIdx", pageIdx, "user", user)

	userID, _ := r.Context().Value("userId").(string)
	dynamicClient, _, err := s.getEbayClientForUser(r.Context(), userID)
	if err != nil {
		slog.Error("Failed to build dynamic client for account", "err", err, "userID", userID)
		http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
		return
	}

	userCtx := context.WithValue(r.Context(), auth.USER, user)
	account, err := dynamicClient.GetAccount(userCtx, pageSize, pageIdx)
	if err != nil {
		slog.Error("failed to get account", "err", err, "user", user)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("successfully got user account info", "user", user, "account", account.AccountID)

	json.NewEncoder(w).Encode(api.UserAccount{
		User:    user,
		Account: account,
	})
}
