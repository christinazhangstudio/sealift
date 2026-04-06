package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/rs/cors"
	"github.tesla.com/chrzhang/sealift/inbox"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SealiftUser struct {
	ID                  primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Email               string              `bson:"email" json:"email"`
	PasswordHash        string              `bson:"passwordHash" json:"passwordHash"`
	EbayDeveloperConfig EbayDeveloperConfig `bson:"ebayDeveloperConfig" json:"ebayDeveloperConfig"`
	CreatedAt           time.Time           `bson:"createdAt" json:"createdAt"`
	DestinationID       string              `bson:"destinationID" json:"destinationID"`
}

type EbayDeveloperConfig struct {
	AppID       string `bson:"appId" json:"appId"`
	DevID       string `bson:"devId" json:"devId"`
	CertID      string `bson:"certId" json:"certId"`
	RedirectURI string `bson:"redirectUri" json:"redirectUri"` // BYOK callback URL
	IsSandbox   bool   `bson:"isSandbox" json:"isSandbox"`
}

// ChallengeResponse for the verification response.
type ChallengeResponse struct {
	ChallengeResponse string `json:"challengeResponse"`
}

var (
	verificationToken = os.Getenv("VERIFICATION_TOKEN")
	endpointURL       = os.Getenv("ENDPOINT_URL") // for notifications
	mongoURI          = os.Getenv("MONGO_URI")
	atlasURI          = os.Getenv("ATLAS_URI")
	frontendURL       = os.Getenv("FRONTEND_URL")
	port              = os.Getenv("PORT")
	ollamaURL         = os.Getenv("OLLAMA_URL")
	ebayScope         = os.Getenv("EBAY_SCOPE")
	ebayAppID         = os.Getenv("EBAY_APP_ID")
	ebayDevID         = os.Getenv("EBAY_DEV_ID")
	ebayCertID        = os.Getenv("EBAY_CERT_ID")
)

func main() {
	ctx := context.Background()

	// local DB setup
	db, err := newDB(ctx, mongoURI)
	if err != nil {
		panic(err)
	}
	defer db.Disconnect(ctx)

	// hybrid DB setup: atlas (cloud) for vector search
	// local as fallback
	var mongoKnowledgeBaseAtlas *mongo.Collection
	if atlasURI != "" {
		atlasClient, err := newDB(ctx, atlasURI)
		if err != nil {
			slog.Warn("Failed to connect to Atlas, using local search fallback", "err", err)
		} else {
			mongoKnowledgeBaseAtlas = atlasClient.Database("sealift").Collection("knowledge_base")
			slog.Info("Successfully connected to Atlas for AI Vector Search")
			defer atlasClient.Disconnect(ctx)
		}
	}

	mongoDB := db.Database("sealift")

	// ensure email uniqueness
	_, _ = mongoDB.Collection("sealift_users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	// set up TTL index so revoked tokens are
	// automatically deleted from Mongo after 24 hours
	_, _ = mongoDB.Collection("revoked_tokens").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "createdAt", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(int32(24 * 60 * 60)),
	})

	sharedClient := &http.Client{Timeout: time.Second * 30}

	inboxCollection := mongoDB.Collection("inbox")
	receiver := &inbox.Receiver{DB: inboxCollection}
	receiver.Init()

	srv := &Server{
		mux:                   http.NewServeMux(),
		httpClient:            sharedClient,
		db:                    mongoDB,
		sealiftUsersCol:       mongoDB.Collection("sealift_users"),
		notesCol:              mongoDB.Collection("notes"),
		ebayAccountsCol:       mongoDB.Collection("ebay_accounts"),
		inboxReceiver:         receiver,
		revokedTokensCol:      mongoDB.Collection("revoked_tokens"),
		knowledgeBaseLocalCol: mongoDB.Collection("knowledge_base"),
		knowledgeBaseAtlasCol: mongoKnowledgeBaseAtlas,
	}

	srv.registerRoutes()

	// conditionally whitelist localhost only
	// during local development.
	// hardcoding 'localhost' in production binaries
	// creates an edge-case CSRF bypass vector!
	var allowedOrigins []string
	if frontendURL != "" &&
		!strings.Contains(frontendURL, "localhost") &&
		!strings.Contains(frontendURL, "host.docker.internal") {
		// production strict
		allowedOrigins = []string{frontendURL}
	} else {
		// local dev relaxed
		allowedOrigins = []string{
			"https://sealift.lystic.dev", "http://localhost:9997", "http://localhost:443"}
	}

	// wrap authHandler with the CORS handler,
	// so CORS allows the blocked requests through
	ch := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
	}).Handler(srv.authMiddleware())

	s := &http.Server{
		Addr:         port,
		Handler:      ch,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Minute, // must be long enough for AI generation + response
		IdleTimeout:  120 * time.Second,
	}

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

func newDB(ctx context.Context, uri string) (*mongo.Client, error) {
	opt := options.Client().ApplyURI(uri)
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

	slog.Debug("connected to mongodb", "uri", uri)

	return db, err
}
