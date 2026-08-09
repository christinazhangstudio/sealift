package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/cors"
	"github.tesla.com/chrzhang/sealift/inbox"
	"github.tesla.com/chrzhang/sealift/secrets"

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
	ebayScope         = os.Getenv("EBAY_SCOPE")
	ebayAppID         = os.Getenv("EBAY_APP_ID")
	ebayDevID         = os.Getenv("EBAY_DEV_ID")
	ebayCertID        = os.Getenv("EBAY_CERT_ID")
)

func main() {
	ctx := context.Background()

	// Credential encryption keys must load before anything reads or writes a
	// stored secret.
	if err := secrets.Init(); err != nil {
		panic(fmt.Sprintf("invalid credential encryption configuration: %v", err))
	}

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

	ensureIndexes(ctx, mongoDB)

	sharedClient := &http.Client{Timeout: time.Second * 30}

	inboxCollection := mongoDB.Collection("inbox")
	receiver := &inbox.Receiver{DB: inboxCollection}
	receiver.Init()

	srv := &Server{
		mux:                   http.NewServeMux(),
		httpClient:            sharedClient,
		db:                    mongoDB,
		sealiftUsersCol:       mongoDB.Collection("sealift_users"),
		ebayAccountsCol:       mongoDB.Collection("ebay_accounts"),
		inboxReceiver:         receiver,
		revokedTokensCol:      mongoDB.Collection("revoked_tokens"),
		knowledgeBaseLocalCol: mongoDB.Collection("knowledge_base"),
		knowledgeBaseAtlasCol: mongoKnowledgeBaseAtlas,
		oauthStatesCol:        mongoDB.Collection("oauth_states"),
		passwordResetsCol:     mongoDB.Collection("password_resets"),
		notificationTestsCol:  mongoDB.Collection("notification_tests"),
	}

	// Bring any pre-encryption credentials up to date before serving traffic.
	encryptStoredCredentials(ctx, mongoDB)

	srv.registerRoutes()

	// Populate the AI knowledge base if it has no chunks from the embedding
	// model currently configured. This covers both a fresh deployment and a
	// change of embedding model (vectors from different models aren't
	// comparable, so old ones are ignored by retrieval and must be replaced).
	// Runs in the background so a slow or unreachable embedding endpoint can't
	// hold up startup.
	go func() {
		if selfHostedEmbeddingURL == "" {
			slog.Info("no embedding endpoint configured; skipping knowledge base ingest")
			return
		}

		ingestCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		count, err := mongoDB.Collection("knowledge_base").CountDocuments(ingestCtx,
			bson.M{"model": selfHostedEmbeddingModel})
		if err != nil {
			slog.Warn("could not check knowledge base state; skipping ingest", "err", err)
			return
		}
		if count > 0 {
			slog.Info("knowledge base already populated", "chunks", count, "model", selfHostedEmbeddingModel)
			return
		}

		slog.Info("knowledge base empty for current model; ingesting docs", "model", selfHostedEmbeddingModel)
		if _, err := srv.ingestDocs(ingestCtx); err != nil {
			slog.Warn("knowledge base ingest failed; AI assistant will answer without docs", "err", err)
		}
	}()

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
		WriteTimeout: 6 * time.Minute, // extended for long-running AI completions / streaming
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
	signal.Notify(sigChan, syscall.SIGTERM)

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
