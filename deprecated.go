package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.tesla.com/chrzhang/sealift/api"
	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
)

// deprecated but preserved for learning purposes.
func deprecated() {
	mux := &http.ServeMux{}
	ctx := context.Background()
	client := &ebay.Client{}

	// doesn't work well with pagination (see user specific method)
	mux.HandleFunc("GET /api/all-payouts", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request", "path", r.URL.Path)

		defaultPageSize := 200 // maximum allowed by ebay, actual default is 20

		pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if err != nil {
			slog.Info(
				"missing page size; using default value",
				"pageSize", defaultPageSize,
			)
			pageSize = defaultPageSize
		}

		pageIdx, err := strconv.Atoi(r.URL.Query().Get("pageIdx"))
		if err != nil {
			slog.Info("missing page index; using 0")
			pageIdx = 0
		}

		users, err := client.Auth.GetUsers(ctx)
		if err != nil {
			slog.Error(
				"failed to get registered users",
				"err", err,
			)
			json.NewEncoder(w).Encode(api.Error{Message: err.Error()})
			return
		}

		var userPayouts []api.UserPayouts
		for _, user := range users {
			ctx = context.WithValue(ctx, auth.USER, user)
			payouts, err := client.GetPayouts(ctx, pageSize, pageIdx)
			if err != nil {
				slog.Error(
					"failed to get payouts",
					"err", err,
					"user", user,
				)
				json.NewEncoder(w).Encode(api.Error{Message: err.Error()})
				return
			}

			userPayouts = append(
				userPayouts,
				api.UserPayouts{
					User:    user,
					Payouts: payouts,
				},
			)
		}

		json.NewEncoder(w).Encode(userPayouts)
	})

	// this is not very performant compared to per user
	// and works poorly for pagination.
	mux.HandleFunc("GET /api/all-listings", func(w http.ResponseWriter, r *http.Request) {
		defaultPageSize := 200 // maximum allowed by ebay, actual default is 25

		pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if err != nil {
			slog.Info(
				"missing page size; using default value",
				"pageSize", defaultPageSize,
			)
			pageSize = defaultPageSize
		}

		pageIdx, err := strconv.Atoi(r.URL.Query().Get("pageIdx"))
		if err != nil {
			slog.Info("missing page index; using 0")
			pageIdx = 0
		}

		layout := "2006-01-02" // YYYY-MM-DD
		startFrom, err := time.Parse(layout, r.URL.Query().Get("startFrom"))
		if err != nil {
			json.NewEncoder(w).Encode(api.Error{Message: "invalid startFrom format. Use YYYY-MM-DD."})
			return
		}

		startTo, err := time.Parse(layout, r.URL.Query().Get("startTo"))
		if err != nil {
			json.NewEncoder(w).Encode(api.Error{Message: "invalid startTo format. Use YYYY-MM-DD."})
			return
		}

		if startTo.Before(startFrom) {
			json.NewEncoder(w).Encode(api.Error{Message: "startTo must be greater than startFrom."})
			return
		}

		daysDiff := startTo.Sub(startFrom).Hours() / 24
		if daysDiff > 120 {
			json.NewEncoder(w).Encode(api.Error{Message: "range cannot exceed 120 days."})
			return
		}

		slog.Info(
			"received request",
			"path", r.URL.Path,
			"pageSize", pageSize,
			"pageIdx", pageIdx,
			"startFrom", startFrom,
			"startTo", startTo,
		)

		users, err := client.Auth.GetUsers(ctx)
		if err != nil {
			slog.Error(
				"failed to get registered users",
				"err", err,
			)
			json.NewEncoder(w).Encode(api.Error{Message: err.Error()})
			return
		}

		var userListings []api.UserListings
		for _, user := range users {
			ctx = context.WithValue(ctx, auth.USER, user)
			listings, err := client.GetSellerList(ctx, pageSize, pageIdx, startFrom, startTo)
			// if the error was that no items were found for the seller
			// for the specified range/page index, that's fine
			// use an empty Listings array for the response.
			if err != nil && err != ebay.ErrHasNoMoreItems {
				slog.Error(
					"failed to get listings",
					"err", err,
					"user", user,
				)
				json.NewEncoder(w).Encode(api.Error{Message: err.Error()})
				return
			}

			userListings = append(
				userListings,
				api.UserListings{
					User:     user,
					Listings: listings,
				},
			)
		}

		json.NewEncoder(w).Encode(userListings)
	})
}
