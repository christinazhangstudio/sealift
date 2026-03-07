package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.tesla.com/chrzhang/sealift/api"
	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/html"
	"github.tesla.com/chrzhang/sealift/inbox"
	"github.tesla.com/chrzhang/sealift/notes"

	"github.com/rs/cors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	verificationToken   = os.Getenv("VERIFICATION_TOKEN")
	endpointURL         = os.Getenv("ENDPOINT_URL") // for notifications
	clientID            = os.Getenv("EBAY_CLIENT_ID")
	clientSecret        = os.Getenv("EBAY_CLIENT_SECRET")
	ebayDevID           = os.Getenv("EBAY_DEV_ID") // only for account info
	ebayURL             = os.Getenv("EBAY_URL")
	ebayTradURL         = os.Getenv("EBAY_TRAD_DLL_URL")
	ebayAuthURL         = os.Getenv("EBAY_AUTH_URL")
	ebayAuthRedirectURI = os.Getenv("EBAY_AUTH_REDIRECT_URI")
	ebaySignIn          = os.Getenv("EBAY_SIGN_IN")
	ebayNotificationURL = os.Getenv("EBAY_NOTIFICATION_URL")
	mongoURI            = os.Getenv("MONGO_URI")
	frontendURL         = os.Getenv("FRONTEND_URL")
	port                = os.Getenv("PORT")
	jwtSecret           = os.Getenv("JWT_SECRET")
)

// ChallengeResponse for the verification response.
type ChallengeResponse struct {
	ChallengeResponse string `json:"challengeResponse"`
}

func main() {
	ctx := context.Background()

	slog.SetLogLoggerLevel(slog.LevelDebug)

	mux := http.NewServeMux()

	// CORS - to allow bypass of CORS block for JS
	// wrap standard serve mus with CORS handler
	//ch := cors.Default().Handler(mux) supports only simple verbs
	ch := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
	}).Handler(mux)

	s := &http.Server{
		Addr:         port,
		Handler:      ch,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	db, err := newDB(ctx)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = db.Disconnect(ctx); err != nil {
			slog.Error("failed to disconnect from db", "err", err)
		}
		slog.Debug("disconnected from db", "err", err)
	}()

	mongoDB := db.Database("sealift")
	mongoUsersCollection := mongoDB.Collection("users")
	mongoInboxCollection := mongoDB.Collection("inbox")

	inboxReceiver := &inbox.Receiver{
		DB: mongoInboxCollection,
	}
	inboxReceiver.Init()

	// reused for now
	// keep in mind will only reuse connections when the resp body has been fully read and closed!
	// otherwise, the application keeps accumulating open connections,
	// especially because the number of connections per host is
	// unlimited by default (transport.MaxConnsPerHost).
	// e.g. `race: limit on 8128 simultaneously alive goroutines is exceeded, dying.`
	httpClient := &http.Client{Timeout: time.Second * 30}
	// ^ 5 seconds can be a little low...
	// Post \"https://api.ebay.com/ws/api.dll\":
	// context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
	// when querying /listings for 200+ items...

	// client to make HTTP requests to eBay APIs.
	client := &ebay.Client{
		Client:          httpClient,
		DB:              mongoUsersCollection,
		URL:             ebayURL,
		TradURL:         ebayTradURL,
		NotificationURL: ebayNotificationURL,
		Auth: &auth.Client{
			Client:       httpClient,
			DB:           mongoUsersCollection,
			AuthURL:      ebayAuthURL,
			RedirectURI:  ebayAuthRedirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			DevID:        ebayDevID,
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request at /", "path", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// required webhook for deletion events
	mux.HandleFunc("/sealift-webhook", deletionNotificationHandler)

	// webhook for seller-specific notifications
	mux.HandleFunc("/sealift-webhook/{user}", notificationHandler(inboxReceiver))

	// user auth and consent page
	// auth-accepted URL is auth-callback
	// https://developer.ebay.com/api-docs/static/oauth-consent-request.html
	mux.HandleFunc("/api/register-seller", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("redirecting to oauth consent page")
		http.Redirect(w, r, ebaySignIn, http.StatusTemporaryRedirect)
	})

	// on-behalf flow for user token
	mux.HandleFunc("/api/auth-callback", func(w http.ResponseWriter, r *http.Request) {
		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			slog.Error("missing auth code", "query", r.URL.Query().Encode())
			html.RenderAuthError(w, "missing auth code: "+r.URL.Query().Encode(), frontendURL)
			return
		}

		slog.Info("received auth code in callback")

		user, err := client.Auth.AuthUser(ctx, authCode)
		if err != nil {
			slog.Error("failed to auth user", "err", err)
			html.RenderAuthError(w, "failed to auth user", frontendURL)
			return
		}

		slog.Info("seller authorized to service", "user", user)

		// Auto-create notification destination for this new user.
		// CreateDestination uses Application Token,
		// so the user context is mainly passing the user ID down.
		authCtx := context.WithValue(ctx, auth.USER, user)
		destinationURL := fmt.Sprintf("%s/%s", endpointURL, user)
		if err := client.CreateDestination(authCtx, destinationURL, verificationToken); err != nil {
			slog.Error("failed to create destination (non-fatal)", "err", err, "user", user)
		} else {
			slog.Info("successfully created notification destination", "user", user)
		}

		html.RenderAuthSuccess(w, frontendURL)
	})

	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request", "path", r.URL.Path)

		users, err := client.Auth.GetUsers(ctx)
		if err != nil {
			slog.Error(
				"failed to get registered users",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(api.Users{Users: users})
	})

	//https://pkg.go.dev/net/http@master#hdr-Precedence-ServeMux
	mux.HandleFunc("DELETE /api/users/{user}", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified.", http.StatusBadRequest)
			return
		}

		slog.Info(
			"received request",
			"path", r.URL.Path,
			"user", user,
		)

		dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		filter := bson.D{{Key: "user", Value: user}}

		// Find user first to get destination ID
		var userDoc struct {
			DestinationID string `bson:"destination_id"`
		}
		err := client.DB.FindOne(dbCtx, filter).Decode(&userDoc)
		if err == mongo.ErrNoDocuments {
			slog.Error(
				"user not found",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err != nil {
			slog.Error(
				"failed to find user",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete user subscriptions first
		ctxWithUser := context.WithValue(ctx, auth.USER, user)
		if err := client.DeleteAllUserSubscriptions(ctxWithUser); err != nil {
			slog.Error("failed to delete all user subscriptions", "err", err, "user", user)
		} else {
			slog.Info("deleted all user subscriptions", "user", user)
		}

		// Delete destination if it exists
		if userDoc.DestinationID != "" {
			slog.Info("deleting notification destination", "user", user, "destinationId", userDoc.DestinationID)

			// Disable destination first before deleting
			destinationURL := fmt.Sprintf("%s/%s", endpointURL, user)
			if err := client.DisableDestination(ctx, userDoc.DestinationID, destinationURL, verificationToken); err != nil {
				slog.Error("failed to disable notification destination", "err", err, "user", user)
			}

			// Attempt to delete destination, but don't block user deletion on failure
			if err := client.DeleteDestination(ctx, userDoc.DestinationID); err != nil {
				slog.Error("failed to delete notification destination", "err", err, "user", user)
			} else {
				slog.Info("deleted notification destination", "destinationId", userDoc.DestinationID)
			}
		}

		result, err := client.DB.DeleteOne(dbCtx, filter)
		if err != nil {
			slog.Error(
				"failed to delete user",
				"err", err,
			)
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
	})

	// gets transaction summaries for all users.
	mux.HandleFunc("GET /api/transaction-summaries", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request", "path", r.URL.Path)

		users, err := client.Auth.GetUsers(ctx)
		if err != nil {
			slog.Error(
				"failed to get registered users",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var userSummaries []api.UserSummary
		for _, user := range users {
			ctx = context.WithValue(ctx, auth.USER, user)
			summary, err := client.GetTransactionSummary(ctx)
			if err != nil {
				slog.Error(
					"failed to get transaction summary",
					"err", err,
					"user", user,
				)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			userSummaries = append(
				userSummaries,
				api.UserSummary{
					User:    user,
					Summary: summary,
				},
			)
		}

		json.NewEncoder(w).Encode(userSummaries)
	})

	mux.HandleFunc("GET /api/payouts/{user}", func(w http.ResponseWriter, r *http.Request) {
		defaultPageSize := 200 // maximum allowed by ebay, actual default is 20
		// recommended to use large page size and paginate results on client side
		// to minimize API calls.

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

		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified.", http.StatusBadRequest)
			return
		}

		slog.Info(
			"received request",
			"path", r.URL.Path,
			"pageSize", pageSize,
			"pageIdx", pageIdx,
			"user", user,
		)

		ctx = context.WithValue(ctx, auth.USER, user)
		payouts, err := client.GetPayouts(ctx, pageSize, pageIdx)
		if err != nil {
			slog.Error(
				"failed to get payouts",
				"err", err,
				"user", user,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userPayouts := api.UserPayouts{
			User:    user,
			Payouts: payouts,
		}

		json.NewEncoder(w).Encode(userPayouts)
	})

	mux.HandleFunc("GET /api/listings/{user}", func(w http.ResponseWriter, r *http.Request) {
		defaultPageSize := 200 // maximum allowed by ebay, actual default is 25
		// recommended to use large page size and paginate results on client side
		// to minimize API calls.

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

		slog.Info(
			"received request",
			"path", r.URL.Path,
			"pageSize", pageSize,
			"pageIdx", pageIdx,
			"startFrom", startFrom,
			"startTo", startTo,
			"user", user,
		)

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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		userListing := api.UserListings{
			User:     user,
			Listings: listings,
		}

		json.NewEncoder(w).Encode(userListing)
	})

	mux.HandleFunc("GET /api/account/{user}", func(w http.ResponseWriter, r *http.Request) {
		defaultPageSize := 200 // maximum allowed by ebay, actual default is 25
		// recommended to use large page size and paginate results on client side
		// to minimize API calls.

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
			slog.Info("missing page index; using 1")
			pageIdx = 1
		}

		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified.", http.StatusBadRequest)
			return
		}

		slog.Info(
			"received request",
			"path", r.URL.Path,
			"pageSize", pageSize,
			"pageIdx", pageIdx,
			"user", user,
		)

		ctx = context.WithValue(ctx, auth.USER, user)
		account, err := client.GetAccount(ctx, pageSize, pageIdx)
		if err != nil {
			slog.Error(
				"failed to get account",
				"err", err,
				"user", user,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Info(
			"successfully got user account info",
			"user", user,
			"account", account.AccountID,
		)

		userListing := api.UserAccount{
			User:    user,
			Account: account,
		}

		json.NewEncoder(w).Encode(userListing)
	})

	mux.HandleFunc("GET /api/notes", func(w http.ResponseWriter, r *http.Request) {
		notesDB := mongoDB.Collection("notes")
		notes, err := notes.GetNotes(ctx, notesDB)
		if err != nil {
			slog.Error(
				"failed to get notes",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(notes)
	})

	mux.HandleFunc("POST /api/notes", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content string `json:"content"`
			Color   string `json:"color"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error(
				"invalid json",
				"err", err,
			)
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		notesDB := mongoDB.Collection("notes")
		err := notes.CreateNote(ctx, notesDB, req.Content, req.Color)
		if err != nil {
			slog.Error(
				"failed to create note",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	mux.HandleFunc("PUT /api/notes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			slog.Error("id not specified")
			http.Error(w, "id not specified.", http.StatusBadRequest)
			return
		}

		var req struct {
			Content string `json:"content"`
			Color   string `json:"color"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error(
				"invalid json",
				"err", err,
			)
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		notesDB := mongoDB.Collection("notes")
		err := notes.UpdateNote(ctx, notesDB, id, req.Content, req.Color)
		if err != nil {
			slog.Error(
				"failed to update note",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	mux.HandleFunc("DELETE /api/notes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			slog.Error("id not specified")
			http.Error(w, "id not specified.", http.StatusBadRequest)
			return
		}

		notesDB := mongoDB.Collection("notes")
		err := notes.DeleteNote(ctx, notesDB, id)
		if err != nil {
			slog.Error(
				"failed to delete notes",
				"err", err,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	// Notification API endpoints
	mux.HandleFunc("GET /api/notification/topic/{topicId}", func(w http.ResponseWriter, r *http.Request) {
		topicID := r.PathValue("topicId")
		if strings.TrimSpace(topicID) == "" {
			slog.Error("topic ID not specified")
			http.Error(w, "topic ID not specified", http.StatusBadRequest)
			return
		}

		slog.Info("received request for notification topic", "topicId", topicID)

		topic, err := client.GetTopic(ctx, topicID)
		if err != nil {
			slog.Error("failed to get notification topic", "err", err, "topicId", topicID)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.NotificationTopic{Topic: topic})
	})

	mux.HandleFunc("GET /api/notification/topics", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request for all notification topics")

		topics, err := client.GetTopics(ctx)
		if err != nil {
			slog.Error("failed to get notification topics", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.NotificationTopics{Topics: topics})
	})

	// Get notification destinations (debug only)
	mux.HandleFunc("GET /api/notification/destinations", func(w http.ResponseWriter, r *http.Request) {
		defaultPageSize := 100 // maximum allowed by ebay, actual default is 20
		pageSize, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
		if err != nil {
			slog.Info(
				"missing page size; using default value",
				"pageSize", defaultPageSize,
			)
			pageSize = defaultPageSize
		}

		dests, err := client.GetDestinations(ctx, pageSize)
		if err != nil {
			slog.Error("failed to create destination", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Group destinations by user (using the Name field)
		userDestMap := make(map[string][]ebay.Destination)
		for _, d := range dests.Destinations {
			user := d.Name
			userDestMap[user] = append(userDestMap[user], d)
		}

		// Convert map to slice for the response
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
	})

	// Delete ALL notification destinations
	// Likely only used during development and troubleshooting.
	// In order to DELETE subscriptions, go through the auth flow, since subscriptions
	// are user-based, and destinations are app-level.
	mux.HandleFunc("DELETE /api/notification/destinations/allusers", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request to delete unused destinations")
		// Get all destinations
		// Use a large limit to hopefully get all of them.
		pageSize := 100
		dests, err := client.GetDestinations(ctx, pageSize)
		if err != nil {
			slog.Error("failed to get destinations", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		deletedCount := 0
		errCount := 0
		for _, d := range dests.Destinations {
			// delete all the notifications
			// EXCEPT for the one used for the app's webhooks
			// (which won't have a user associated to its name field)
			if d.Name != "" {
				// Disable destination first before deleting
				if err := client.DisableDestination(ctx, d.DestinationID, d.DeliveryConfig.Endpoint, verificationToken); err != nil {
					slog.Error("failed to disable destination", "destinationId", d.DestinationID, "err", err)
				}

				if err := client.DeleteDestination(ctx, d.DestinationID); err != nil {
					slog.Error("failed to delete destination", "destinationId", d.DestinationID, "err", err)
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
	})

	// Create a notification subscription for a seller
	mux.HandleFunc("POST /api/notification/users/{user}/subscriptions", func(w http.ResponseWriter, r *http.Request) {
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

		ctx = context.WithValue(ctx, auth.USER, user)
		subID, err := client.CreateUserSubscription(ctx, req.TopicID)
		if err != nil {
			slog.Error("failed to create subscription", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(api.CreateUserSubscription{SubscriptionID: subID})
	})

	// Get subscriptions for a seller
	mux.HandleFunc("GET /api/notification/users/{user}/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified", http.StatusBadRequest)
			return
		}

		slog.Info("received request for notification subscriptions", "user", user)

		ctx = context.WithValue(ctx, auth.USER, user)
		subs, err := client.GetUserSubscriptions(ctx)
		if err != nil {
			slog.Error("failed to get subscriptions", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.NotificationSubscriptions{Subscriptions: subs})
	})

	// Enable a subscription for a seller
	mux.HandleFunc("POST /api/notification/users/{user}/subscriptions/enable", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified", http.StatusBadRequest)
			return
		}

		slog.Info("received request to enable subscriptions", "user", user)

		ctx = context.WithValue(ctx, auth.USER, user)
		subs, err := client.EnableUserSubscriptions(ctx)
		if err != nil {
			slog.Error("failed to enable subscriptions", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.NotificationSubscriptions{Subscriptions: subs})
	})

	// Test a subscription for a seller
	mux.HandleFunc("POST /api/notification/users/{user}/subscriptions/{subscriptionId}/test", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		subscriptionID := r.PathValue("subscriptionId")
		if user == "" || subscriptionID == "" {
			http.Error(w, "user and subscription ID required", http.StatusBadRequest)
			return
		}

		slog.Info("received request to test subscription", "user", user, "subscriptionId", subscriptionID)

		ctx = context.WithValue(ctx, auth.USER, user)
		err := client.TestUserSubscription(ctx, subscriptionID)
		if err != nil {
			slog.Error("failed to test subscription", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		slog.Info("triggered test payload for subscription", "subscriptionId", subscriptionID, "user", user)

		w.WriteHeader(http.StatusNoContent)
	})

	// trash a specific notification
	mux.HandleFunc("PUT /api/inbox/{user}/{notificationId}/trash", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		notificationID := r.PathValue("notificationId")
		if user == "" || notificationID == "" {
			http.Error(w, "missing user or notification id", http.StatusBadRequest)
			return
		}

		slog.Info("trashing notification", "user", user, "notificationId", notificationID)
		if err := inboxReceiver.TrashNotification(ctx, user, notificationID); err != nil {
			slog.Error("failed to trash notification", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	// mark a specific notification as read in the inbox
	mux.HandleFunc("PUT /api/inbox/{user}/{notificationId}/mark_read", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		notificationID := r.PathValue("notificationId")
		if user == "" || notificationID == "" {
			http.Error(w, "missing user or notification id", http.StatusBadRequest)
			return
		}

		slog.Info("marking notification as read", "user", user, "notificationId", notificationID)
		if err := inboxReceiver.ReadNotification(ctx, user, notificationID); err != nil {
			slog.Error("failed to mark notification as read", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	// permanently delete a specific notification from trash
	mux.HandleFunc("DELETE /api/inbox/{user}/{notificationId}/trash", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		notificationID := r.PathValue("notificationId")
		if user == "" || notificationID == "" {
			http.Error(w, "missing user or notification id", http.StatusBadRequest)
			return
		}

		slog.Info("permanently deleting notification", "user", user, "notificationId", notificationID)
		if err := inboxReceiver.DeletePermanent(ctx, user, notificationID); err != nil {
			slog.Error("failed to permanently delete notification", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	go func() {
		slog.Debug("starting server", "port", port)
		err = s.ListenAndServe()
		if err != nil {
			slog.Error("server failed", "err", err)
		}
	}()

	// custom server for graceful shutdown
	// rcv kill command/interrupt
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt)
	signal.Notify(sigChan, os.Kill)

	// reading from a channel will block until message is consumed
	// once the message is consumed, server is shutdown
	sig := <-sigChan
	slog.Debug("received shutdown signal; gracefully shutting down", "sig", sig)

	// graceful shutdown waits for requests to be done until shutting down the server
	// useful for finishing up database transactions
	// first create a context with duration of 30 seconds
	// (give graceful shutdown 30 sec until forcefully shutting down)
	tc, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.Shutdown(tc)
	cancel()

	slog.Debug("server stopped!")
}

func newDB(ctx context.Context) (*mongo.Client, error) {
	opt := options.Client().ApplyURI(mongoURI)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	db, err := mongo.Connect(ctx, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to connect DB; %w", err)
	}

	err = db.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping DB; %w", err)
	}

	slog.Debug("connected to mongodb")

	return db, err
}

func notificationHandler(inbox *inbox.Receiver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// handle verification challenge or SSE connection
			challengeCode := r.URL.Query().Get("challenge_code")
			if challengeCode == "" {
				// check if this is an SSE connection request
				if r.Header.Get("Accept") == "text/event-stream" {
					// headers for Server-Sent Events
					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Cache-Control", "no-cache")
					w.Header().Set("Connection", "keep-alive")
					w.Header().Set("Access-Control-Allow-Origin", "*")

					// buffer channel for this specific connection
					// for 100 messages so that no messages are lost
					// if the browser is not reading SSE events fast enough
					// (also not unbuffered because the code on the rcv e.g. Marshal
					// can cause dropped messages if they arrive very closely together)
					connChan := make(chan map[string]interface{}, 100)

					// add this connection channel, specific to the user
					inbox.AddClient(user, connChan)

					// cleanup when the connection is closed
					defer func() {
						inbox.RemoveClient(user, connChan)
						close(connChan)
					}()

					// send initial payload (for historical messages)
					userWebhooks, err := inbox.GetPastNotifications(r.Context(), user)
					if err != nil {
						slog.Error("failed to get initial webhooks from db", "err", err, "user", user)
					}

					if len(userWebhooks) > 0 {
						data, _ := json.Marshal(userWebhooks)
						fmt.Fprintf(w, "event: initial\ndata: %s\n\n", data)
						w.(http.Flusher).Flush() // actually write
					}

					// listen for new messages and push them
					for {
						select {
						case msg := <-connChan:
							data, err := json.Marshal(msg)
							if err != nil {
								slog.Error("failed to marshal message", "err", err)
								continue
							}
							fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
							w.(http.Flusher).Flush() // actually write
						case <-r.Context().Done():
							return // client disconnected
						}
					}
				}

				// if no challenge code and not SSE, just return the recent webhooks for this user
				userWebhooks, err := inbox.GetPastNotifications(r.Context(), user)
				if err != nil {
					http.Error(w, "error pulling webhooks from data store", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				if userWebhooks == nil {
					json.NewEncoder(w).Encode([]interface{}{})
					return
				}
				json.NewEncoder(w).Encode(userWebhooks)
				return
			}

			// compute hash for challenge code + verification token + endpoint URL (make sure to use the right URL)
			hashInput := challengeCode + verificationToken + endpointURL + "/" + user
			hash := sha256.Sum256([]byte(hashInput))
			hashString := fmt.Sprintf("%x", hash)

			slog.Info("computed hash for challenge code", "url", endpointURL+"/"+user, "user", user)

			resp := ChallengeResponse{ChallengeResponse: hashString}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "invalid challenge resp", http.StatusBadRequest)
				return
			}

		case http.MethodPost:
			// handle notification for specific seller
			var notif map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&notif); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}

			var payload ebay.NotificationPayload
			if notifBytes, err := json.Marshal(notif); err == nil {
				json.Unmarshal(notifBytes, &payload)
			}

			slog.Info("received notification for seller", "user", user, "eventDate", payload.Notification.EventDate, "sender", payload.Notification.Data.SenderUserName)

			err := inbox.PushNotification(r.Context(), user, notif)
			if err != nil {
				slog.Error("failed to store and broadcast notification", "err", err)
				// allow the platform to know that we received the message,
				// even if it was hasn't handled correctly by the receiver
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func deletionNotificationHandler(w http.ResponseWriter, r *http.Request) {
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
