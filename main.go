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
	"time"

	"github.tesla.com/chrzhang/sealift/api"
	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/html"

	"github.com/rs/cors"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	verificationToken   = os.Getenv("VERIFICATION_TOKEN")
	endpointURL         = os.Getenv("ENDPOINT_URL") // for notifications
	clientID            = os.Getenv("EBAY_CLIENT_ID")
	clientSecret        = os.Getenv("EBAY_CLIENT_SECRET")
	ebayURL             = os.Getenv("EBAY_URL")
	ebayTradURL         = os.Getenv("EBAY_TRAD_DLL_URL")
	ebayAuthURL         = os.Getenv("EBAY_AUTH_URL")
	ebayAuthRedirectURI = os.Getenv("EBAY_AUTH_REDIRECT_URI")
	ebaySignIn          = os.Getenv("EBAY_SIGN_IN")
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
	ch := cors.Default().Handler(mux)

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
	mongoCollection := mongoDB.Collection("users")

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
		Client:  httpClient,
		DB:      mongoCollection,
		URL:     ebayURL,
		TradURL: ebayTradURL,
		Auth: &auth.Client{
			Client:       httpClient,
			DB:           mongoCollection,
			AuthURL:      ebayAuthURL,
			RedirectURI:  ebayAuthRedirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request at /", "path", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	mux.HandleFunc("/sealift-webhook", notificationHandler)

	// // JWT-based login with CSRF middleware
	// mux.HandleFunc("GET /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
	// 	slog.Info("received request to login", "part", r.URL.Path)

	// 	// this is ok with https
	// 	var creds struct {
	// 		Username string `json:"username"`
	// 		Password string `json:"password"`
	// 	}
	// 	err := json.NewDecoder(r.Body).Decode(&creds)
	// 	if err != nil {
	// 		slog.Error(
	// 			"failed to auth user; invalid creds",
	// 			"err", err,
	// 		)
	// 		http.Error(w, "failed to auth user; invalid creds", http.StatusBadRequest)
	// 		return
	// 	}

	// 	if creds.Username == "" || creds.Password == "" {
	// 		http.Error(w, "username and password not supplied", http.StatusBadRequest)
	// 		return
	// 	}

	// 	mongoCollection := mongoDB.Collection("")

	// 	filter := bson.D{{Key: "user", Value: creds.Username}}
	// 	var token UserTokenDocument
	// 	err = .FindOne(ctx, filter).Decode(&token)
	// 	if err == mongo.ErrNoDocuments {
	// 		http.Error(w, "invalid user credentials", http.StatusUnauthorized)
	// 		return
	// 	}

	// 	if err != nil {
	// 		http.Error("failed to find token for user; %w", err)
	// 	}

	// 	// JWTs are signed with a secret key; storing
	// 	// it in FE (client-side code/env vars/etc)
	// 	// exposes it to attackers via XSS and browser dev tools
	// 	// (via localStorage and non-HTTP-only cookies).

	// })

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
			slog.Error("missing auth code")
			html.RenderAuthError(w, "missing auth code", frontendURL)
			return
		}

		slog.Info("received auth code in callback")

		err := client.Auth.AuthUser(ctx, authCode)
		if err != nil {
			slog.Error("failed to auth user", "err", err)
			html.RenderAuthError(w, "failed to auth user", frontendURL)
		}

		slog.Info("seller authorized to service")

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

		// TODO: delete user

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
			pageIdx = 0
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
