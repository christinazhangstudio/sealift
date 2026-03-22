package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.tesla.com/chrzhang/sealift/api"
	"github.tesla.com/chrzhang/sealift/auth"
	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/html"
	"github.tesla.com/chrzhang/sealift/inbox"
	"github.tesla.com/chrzhang/sealift/notes"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type EbayDeveloperConfig struct {
	AppID       string `bson:"appId" json:"appId"`
	DevID       string `bson:"devId" json:"devId"`
	CertID      string `bson:"certId" json:"certId"`
	RedirectURI string `bson:"redirectUri" json:"redirectUri"` // BYOK callback URL
}

type SealiftUser struct {
	ID                  primitive.ObjectID  `bson:"_id,omitempty" json:"id"`
	Email               string              `bson:"email" json:"email"`
	PasswordHash        string              `bson:"passwordHash" json:"passwordHash"`
	EbayDeveloperConfig EbayDeveloperConfig `bson:"ebayDeveloperConfig" json:"ebayDeveloperConfig"`
	CreatedAt           time.Time           `bson:"createdAt" json:"createdAt"`
	DestinationID       string              `bson:"destinationID" json:"destinationID"`
}

type KnowledgeChunk struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Source    string             `bson:"source" json:"source"`
	Text      string             `bson:"text" json:"text"`
	Embedding []float32          `bson:"embedding" json:"embedding"`
	CreatedAt time.Time          `bson:"createdAt" json:"createdAt"`
}

var (
	verificationToken   = os.Getenv("VERIFICATION_TOKEN")
	endpointURL         = os.Getenv("ENDPOINT_URL") // for notifications
	ebayURL             = os.Getenv("EBAY_URL")
	ebayTradURL         = os.Getenv("EBAY_TRAD_DLL_URL")
	ebayAuthURL         = os.Getenv("EBAY_AUTH_URL")
	ebayNotificationURL = os.Getenv("EBAY_NOTIFICATION_URL")
	mongoURI            = os.Getenv("MONGO_URI")
	atlasURI            = os.Getenv("ATLAS_URI")
	frontendURL         = os.Getenv("FRONTEND_URL")
	port                = os.Getenv("PORT")
	ollamaURL           = os.Getenv("OLLAMA_URL")
)

// ChallengeResponse for the verification response.
type ChallengeResponse struct {
	ChallengeResponse string `json:"challengeResponse"`
}

type JWKS struct {
	Keys []struct {
		Alg string `json:"alg"`
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

var cachedPubKey *rsa.PublicKey

func fetchPublicKey() (*rsa.PublicKey, error) {
	if cachedPubKey != nil {
		return cachedPubKey, nil
	}

	// Dynamic fetching allows Go to adapt to Next.js key rotations without shared env vars.
	// We use host.docker.internal to access Next.js running on the host from inside the Go container.
	url := fmt.Sprintf("http://host.docker.internal:%s/api/jwks", os.Getenv("NEXT_PORT"))
	if os.Getenv("NEXT_PORT") == "" {
		url = "http://host.docker.internal:9997/api/jwks"
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS json: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	if err != nil {
		return nil, err
	}

	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	cachedPubKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	return cachedPubKey, nil
}

func main() {
	ctx := context.Background()

	db, err := newDB(ctx, mongoURI)
	if err != nil {
		panic(err)
	}
	defer db.Disconnect(ctx)

	// AI Hybrid Setup: Secondary Atlas client for Vector Search
	var mongoKnowledgeBaseAtlas *mongo.Collection
	if atlasURI != "" {
		atlasClient, err := newDB(ctx, atlasURI)
		if err == nil {
			mongoKnowledgeBaseAtlas = atlasClient.Database("sealift").Collection("knowledge_base")
			slog.Info("Successfully connected to Atlas for AI Vector Search")
			defer atlasClient.Disconnect(ctx)
		} else {
			slog.Warn("Failed to connect to Atlas, using local search fallback", "err", err)
		}
	}

	mongoDB := db.Database("sealift")
	mongoSealiftUsers := mongoDB.Collection("sealift_users") // Users and their Dev Configs
	mongoEbayAccounts := mongoDB.Collection("ebay_accounts") // eBay OAuth Tokens (formerly 'users')
	mongoInboxCollection := mongoDB.Collection("inbox")
	mongoRevokedTokens := mongoDB.Collection("revoked_tokens")
	mongoKnowledgeBaseLocal := mongoDB.Collection("knowledge_base")

	// Ensure email uniqueness
	_, _ = mongoSealiftUsers.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	// Set up TTL index so revoked tokens are automatically deleted from Mongo after 24 hours
	_, _ = mongoRevokedTokens.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "createdAt", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(int32(24 * 60 * 60)),
	})

	mux := http.NewServeMux()

	sharedClient := &http.Client{Timeout: time.Second * 30}
	inboxReceiver := &inbox.Receiver{
		DB: mongoInboxCollection,
	}
	inboxReceiver.Init()

	getEbayClientForUser := func(reqCtx context.Context, strictUserID string) (*ebay.Client, SealiftUser, error) {
		var user SealiftUser
		objID, err := primitive.ObjectIDFromHex(strictUserID)
		if err != nil {
			return nil, user, err
		}
		if err := mongoSealiftUsers.FindOne(reqCtx, bson.M{"_id": objID}).Decode(&user); err != nil {
			return nil, user, err
		}

		return &ebay.Client{
			Client:          sharedClient,
			DB:              mongoEbayAccounts,
			URL:             ebayURL,
			TradURL:         ebayTradURL,
			NotificationURL: ebayNotificationURL,
			Auth: &auth.Client{
				Client:       sharedClient,
				DB:           mongoEbayAccounts,
				AuthURL:      ebayAuthURL,
				RedirectURI:  user.EbayDeveloperConfig.RedirectURI,
				ClientID:     user.EbayDeveloperConfig.AppID,
				ClientSecret: user.EbayDeveloperConfig.CertID,
				DevID:        user.EbayDeveloperConfig.DevID,
			},
		}, user, nil
	}

	// Public client for initial setup
	client := &ebay.Client{
		Client:          sharedClient,
		DB:              mongoEbayAccounts,
		URL:             ebayURL,
		TradURL:         ebayTradURL,
		NotificationURL: ebayNotificationURL,
		Auth: &auth.Client{
			Client:  sharedClient,
			DB:      mongoEbayAccounts,
			AuthURL: ebayAuthURL,
		},
	}

	// Ingest revoked JWTs from NextAuth
	mux.HandleFunc("/api/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			JTI string `json:"jti"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.JTI == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Insert the UUID into the blocked collection
		_, err := mongoRevokedTokens.InsertOne(r.Context(), bson.M{
			"jti":       payload.JTI,
			"createdAt": time.Now(),
		})
		if err != nil && !mongo.IsDuplicateKeyError(err) {
			slog.Error("failed to save revoked token", "err", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	// INGRESS: Register New Sealift User (Called by Next.js Frontend)
	mux.HandleFunc("/api/register-user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var user SealiftUser
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil || user.Email == "" || user.PasswordHash == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		user.CreatedAt = time.Now()
		result, err := mongoSealiftUsers.InsertOne(r.Context(), user)
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				http.Error(w, "Email already exists", http.StatusConflict)
				return
			}
			slog.Error("Failed to create user", "err", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		newTenantID := result.InsertedID.(primitive.ObjectID).Hex()
		slog.Info("Created new Sealift tenant", "tenantID", newTenantID)

		// Create tenant-level notification destination immediately
		go func(tenantID string) {
			slog.Info("Registering tenant-level notification destination", "tenantID", tenantID)
			dynamicClient, _, err := getEbayClientForUser(context.Background(), tenantID)
			if err != nil {
				slog.Error("Registration background task failed: client-init", "err", err, "tenantID", tenantID)
				return
			}

			// We use the tenantID as the "name" for the destination for easier tracking
			destCtx := context.WithValue(context.Background(), auth.USER, tenantID)
			destinationURL := fmt.Sprintf("%s/tenant/%s", endpointURL, tenantID)

			destID, err := dynamicClient.CreateDestination(destCtx, destinationURL, verificationToken)
			if err != nil {
				slog.Warn("Registration background task warning: destination already exists or failed", "err", err, "url", destinationURL)
			} else {
				slog.Info("Successfully created tenant notification destination", "tenantID", tenantID, "destID", destID)
				// Store the destination ID on the tenant record
				objID, _ := primitive.ObjectIDFromHex(tenantID)
				mongoSealiftUsers.UpdateOne(context.Background(), bson.M{"_id": objID}, bson.M{"$set": bson.M{"destinationID": destID}})
			}
		}(newTenantID)

		json.NewEncoder(w).Encode(map[string]interface{}{"id": result.InsertedID})
	})

	// INGRESS: Get User by Email for NextAuth Login Verification
	mux.HandleFunc("/api/internal/get-user", func(w http.ResponseWriter, r *http.Request) {
		// Only allow local calls in production context. Skipping auth middleware as it's internal.
		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, "Email required", http.StatusBadRequest)
			return
		}
		var user SealiftUser
		if err := mongoSealiftUsers.FindOne(r.Context(), bson.M{"email": email}).Decode(&user); err != nil {
			if err == mongo.ErrNoDocuments {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(user)
	})
	// AI POC: Documentation Ingestion (Sequential Step 1)
	mux.HandleFunc("POST /api/ai/ingest", func(w http.ResponseWriter, r *http.Request) {
		docsPath := "docs"
		files, err := os.ReadDir(docsPath)
		if err != nil {
			slog.Error("Failed to read docs directory", "err", err)
			http.Error(w, "Could not find docs directory", http.StatusInternalServerError)
			return
		}

		var ingestedCount int
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".md") {
				continue
			}

			content, err := os.ReadFile(fmt.Sprintf("%s/%s", docsPath, f.Name()))
			if err != nil {
				continue
			}

			// Simple chunking: split by paragraphs for POC
			chunks := strings.Split(string(content), "\n\n")
			for _, text := range chunks {
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}

				embedding, err := getOllamaEmbedding(text)
				if err != nil {
					slog.Warn("Failed to get embedding from Ollama", "err", err)
					continue
				}

				chunk := KnowledgeChunk{
					Source:    f.Name(),
					Text:      text,
					Embedding: embedding,
					CreatedAt: time.Now(),
				}

				_, err = mongoKnowledgeBaseLocal.InsertOne(r.Context(), chunk)
				if err != nil {
					slog.Error("Failed to save chunk to Local Mongo", "err", err)
				}
				if mongoKnowledgeBaseAtlas != nil {
					_, err = mongoKnowledgeBaseAtlas.InsertOne(r.Context(), chunk)
					if err != nil {
						slog.Error("Failed to save chunk to Atlas Mongo", "err", err)
					}
				}
				ingestedCount++
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "chunks_ingested": ingestedCount})
	})

	// AI POC: Documentation Ask (Sequential Step 2 & 3 Combined)
	mux.HandleFunc("GET /api/ai/ask", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if query == "" {
			http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
			return
		}

		simThresholdStr := os.Getenv("AI_SIMILARITY_THRESHOLD")
		var simThreshold float32 = 0.30 // Default threshold
		if simThresholdStr != "" {
			if val, err := strconv.ParseFloat(simThresholdStr, 32); err == nil {
				simThreshold = float32(val)
			}
		}

		// 1. Get embedding for the user question
		queryEmbedding, err := getOllamaEmbedding(query)
		if err != nil {
			slog.Error("Failed to embed query", "err", err)
			http.Error(w, "AI service unavailable", http.StatusInternalServerError)
			return
		}

		// 2. Retrieval: Search MongoDB for the most relevant chunks
		pipeline := mongo.Pipeline{
			{
				{Key: "$vectorSearch", Value: bson.D{
					{Key: "index", Value: "vector_index"}, // Must match the name in MongoDB Atlas
					{Key: "path", Value: "embedding"},
					{Key: "queryVector", Value: queryEmbedding},
					{Key: "numCandidates", Value: 10},
					{Key: "limit", Value: 3},
				}},
			},
		}

		var chunks []KnowledgeChunk

		// Step 2a: Try High-Performance Atlas Vector Search first (Threshold: 0.7 for Vector)
		if mongoKnowledgeBaseAtlas != nil {
			slog.Debug("Attempting Atlas Vector Search...")
			cursor, err := mongoKnowledgeBaseAtlas.Aggregate(r.Context(), pipeline)
			if err == nil {
				defer cursor.Close(r.Context())
				var atlasChunks []KnowledgeChunk
				if err := cursor.All(r.Context(), &atlasChunks); err == nil {
					for _, c := range atlasChunks {
						score := cosineSimilarity(queryEmbedding, c.Embedding)
						// Nomic embeddings typically range 0.25 - 0.7 for valid matches
						if score > simThreshold {
							chunks = append(chunks, c)
						}
					}
					if len(chunks) > 0 {
						slog.Info("Vector search succeeded on Atlas", "count", len(chunks))
					} else if len(atlasChunks) > 0 {
						slog.Info("Atlas found chunks but all were below threshold", "highestScore", cosineSimilarity(queryEmbedding, atlasChunks[0].Embedding))
					}
				} else {
					slog.Warn("Vector search fetch failed with error", "err", err)
				}
			} else {
				slog.Warn("Vector search aggregate failed with error", "err", err)
			}
		}

		// Step 2b: Fallback to Local Search if Atlas is missing or empty
		if len(chunks) == 0 {
			slog.Debug("Atlas search empty or failed, trying local fallback...")
			allCursor, err := mongoKnowledgeBaseLocal.Find(r.Context(), bson.M{})
			if err != nil {
				slog.Error("Local Knowledge base inaccessible", "err", err)
			} else {
				defer allCursor.Close(r.Context())
				var allChunks []KnowledgeChunk
				if err := allCursor.All(r.Context(), &allChunks); err == nil {
					type ScoredChunk struct {
						Chunk KnowledgeChunk
						Score float32
					}
					var scored []ScoredChunk
					for _, c := range allChunks {
						score := cosineSimilarity(queryEmbedding, c.Embedding)

						// Similarity Threshold: configurable explicitly via AI_SIMILARITY_THRESHOLD
						if score > simThreshold {
							scored = append(scored, ScoredChunk{Chunk: c, Score: score})
						} else if score > (simThreshold - 0.10) {
							// For debugging: see what closely missed the threshold
							slog.Info("Local chunk closely missed threshold", "score", score, "source", c.Source)
						}
					}

					sort.Slice(scored, func(i, j int) bool {
						return scored[i].Score > scored[j].Score
					})

					limit := 3
					if len(scored) < limit {
						limit = len(scored)
					}
					for i := 0; i < limit; i++ {
						chunks = append(chunks, scored[i].Chunk)
					}
					if len(chunks) > 0 {
						slog.Info("Local search fallback successful", "count", len(chunks))
					}
				}
			}
		}

		// 3. Generation: Combine context and ask Llama
		contextText := ""
		isCasualChat := len(chunks) == 0

		if !isCasualChat {
			for i, chunk := range chunks {
				contextText += fmt.Sprintf("[%d] Source: %s\nContent: %s\n\n", i+1, chunk.Source, chunk.Text)
			}
		}

		slog.Info("Requesting AI Generation", "isCasual", isCasualChat)
		answer, err := getCompletion(query, contextText, isCasualChat)
		if err != nil {
			slog.Error("AI completion failed", "err", err)
			http.Error(w, "Failed to generate answer", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"query":   query,
			"answer":  answer,
			"sources": chunks,
		})
	})

	// CORS - to allow bypass of CORS block for JS
	// wrap standard serve mus with CORS handler
	//ch := cors.Default().Handler(mux) supports only simple verbs
	authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Incoming request", "method", r.Method, "path", r.URL.Path)
		// Only protect specific API endpoints and SSE stream
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/sealift-webhook/") {
			// Skip unauthenticated paths: webhooks and login flow
			isWebhook := r.URL.Path == "/sealift-webhook" || strings.HasPrefix(r.URL.Path, "/sealift-webhook/tenant/")
			isPublicAPI := r.URL.Path == "/api/revoke" || r.URL.Path == "/api/register-user" || strings.HasPrefix(r.URL.Path, "/api/internal/") || r.URL.Path == "/api/auth-callback" || strings.HasPrefix(r.URL.Path, "/api/ai/")

			if isWebhook || isPublicAPI {
				mux.ServeHTTP(w, r)
				return
			}

			// Look for the Auth.js cookie
			var tokenString string
			cookieNames := []string{
				"authjs.session-token",          // Default local
				"__Secure-authjs.session-token", // Secure production
			}

			for _, name := range cookieNames {
				if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
					tokenString = cookie.Value
					break
				}
			}

			// Ensure they actually sent a cookie
			if tokenString == "" {
				slog.Warn("Unauthorized access attempt - no authjs cookie found", "path", r.URL.Path)
				http.Error(w, "Unauthorized: No session cookie", http.StatusUnauthorized)
				return
			}

			// Validate the JWT signature natively using Go and Asymmetric RS256 keys
			token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return fetchPublicKey()
			})

			if err != nil || !token.Valid {
				slog.Error("Unauthorized - invalid JWT signature", "err", err, "path", r.URL.Path)
				http.Error(w, "Unauthorized: Invalid JWT", http.StatusUnauthorized)
				return
			}

			// Validate database blocklist (Stateless Revocation)
			var subject string
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if jti, ok := claims["jti"].(string); ok && jti != "" {
					var result bson.M
					err := mongoRevokedTokens.FindOne(r.Context(), bson.M{"jti": jti}).Decode(&result)
					// If err is NOT ErrNoDocuments, it means the token was successfully found in the blocklist
					if err != mongo.ErrNoDocuments {
						slog.Warn("Unauthorized - token is revoked", "jti", jti)
						http.Error(w, "Unauthorized: Token Revoked", http.StatusUnauthorized)
						return
					}
				}
				if sub, ok := claims["sub"].(string); ok {
					subject = sub
				}
			}

			// Add the authenticated User ID (sub) to the request context
			if subject != "" {
				r = r.WithContext(context.WithValue(r.Context(), "userId", subject))
			}
		}

		// Proceed to the normal route handling
		mux.ServeHTTP(w, r)
	})

	// Conditionally whitelist localhost only during local development.
	// Hardcoding 'localhost' in production binaries creates an edge-case CSRF bypass vector!
	var allowedOrigins []string
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL != "" && !strings.Contains(frontendURL, "localhost") {
		// Production Strict
		allowedOrigins = []string{frontendURL}
	} else {
		// Local Dev Relaxed
		allowedOrigins = []string{"https://sealift.lystic.dev", "http://localhost:9997", "http://localhost:443"}
	}

	// Wrap our authHandler with the CORS handler, so CORS allows the blocked requests through
	ch := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
	}).Handler(authHandler)

	s := &http.Server{
		Addr:         port,
		Handler:      ch,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("received request at /", "path", r.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// required webhook for deletion events
	mux.HandleFunc("/sealift-webhook", func(w http.ResponseWriter, r *http.Request) {
		deletionNotificationHandler(w, r, client)
	})

	// Webhook for all seller notifications under a Sealift Tenant
	mux.HandleFunc("/sealift-webhook/tenant/{tenantID}", notificationHandler(inboxReceiver, getEbayClientForUser))

	// SSE stream for frontend updates
	mux.HandleFunc("GET /api/notifications/{user}/stream", sseHandler(inboxReceiver, client))

	// user auth and consent page (BYOK Dynamic Route)
	mux.HandleFunc("/api/register-seller", func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value("userId").(string)
		if !ok || userID == "" {
			http.Error(w, "Unauthorized Context", http.StatusUnauthorized)
			return
		}

		_, user, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			http.Error(w, "Failed to load Dev Configs", http.StatusInternalServerError)
			return
		}

		baseAuthURL := "https://auth.ebay.com/oauth2/authorize?response_type=code&scope=https://api.ebay.com/oauth/api_scope https://api.ebay.com/oauth/api_scope/sell.marketing.readonly https://api.ebay.com/oauth/api_scope/sell.marketing https://api.ebay.com/oauth/api_scope/sell.inventory.readonly https://api.ebay.com/oauth/api_scope/sell.inventory https://api.ebay.com/oauth/api_scope/sell.account.readonly https://api.ebay.com/oauth/api_scope/sell.account https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly https://api.ebay.com/oauth/api_scope/sell.fulfillment https://api.ebay.com/oauth/api_scope/sell.analytics.readonly https://api.ebay.com/oauth/api_scope/sell.finances https://api.ebay.com/oauth/api_scope/sell.payment.dispute https://api.ebay.com/oauth/api_scope/commerce.identity.readonly https://api.ebay.com/oauth/api_scope/sell.reputation https://api.ebay.com/oauth/api_scope/sell.reputation.readonly https://api.ebay.com/oauth/api_scope/commerce.notification.subscription https://api.ebay.com/oauth/api_scope/commerce.notification.subscription.readonly https://api.ebay.com/oauth/api_scope/sell.stores https://api.ebay.com/oauth/api_scope/sell.stores.readonly https://api.ebay.com/oauth/scope/sell.edelivery https://api.ebay.com/oauth/api_scope/commerce.message"
		consentURL := fmt.Sprintf("%s&client_id=%s&redirect_uri=%s&state=%s", baseAuthURL, user.EbayDeveloperConfig.AppID, user.EbayDeveloperConfig.RedirectURI, userID)

		slog.Info("redirecting to oauth consent page", "userId", userID)
		http.Redirect(w, r, consentURL, http.StatusTemporaryRedirect)
	})

	// on-behalf flow for user token (BYOK Handshake)
	mux.HandleFunc("/api/auth-callback", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("TRACE: /api/auth-callback reached", "url", r.URL.String())
		userID, ok := r.Context().Value("userId").(string)
		if !ok || userID == "" {
			// Fallback to 'state' parameter for cross-domain tunnels (localhost vs ngrok)
			userID = r.URL.Query().Get("state")
		}

		if userID == "" {
			html.RenderAuthError(w, "Unauthorized session", frontendURL)
			return
		}

		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			slog.Error("missing auth code", "query", r.URL.Query().Encode())
			html.RenderAuthError(w, "missing auth code", frontendURL)
			return
		}

		slog.Info("received auth code in callback, resolving dynamic client...")

		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client during auth-callback", "err", err, "userID", userID)
			html.RenderAuthError(w, "database mapping failure", frontendURL)
			return
		}

		ebayUserStore, err := dynamicClient.Auth.AuthUser(ctx, authCode, userID)
		if err != nil {
			slog.Error("Failed to auth user/write to mongo", "err", err, "userID", userID)
			html.RenderAuthError(w, "failed to auth user", frontendURL)
			return
		}

		slog.Info("Handshake Complete: seller authorized and written to DB", "ebayUser", ebayUserStore, "tenantID", userID)

		html.RenderAuthSuccess(w, frontendURL)
	})

	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		userID, _ := r.Context().Value("userId").(string)
		slog.Info("received request", "path", r.URL.Path, "userId", userID)

		users, err := client.Auth.GetUsers(ctx, userID)
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

		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for user delete", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		filter := bson.M{
			"user":            user,
			"sealift_user_id": userID,
		}

		// Find user first to get destination ID
		var userDoc struct {
			DestinationID string `bson:"destination_id"`
		}
		err = client.DB.FindOne(dbCtx, filter).Decode(&userDoc)
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
		if err := dynamicClient.DeleteAllUserSubscriptions(ctxWithUser); err != nil {
			slog.Error("failed to delete all user subscriptions", "err", err, "user", user)
		} else {
			slog.Info("deleted all user subscriptions", "user", user)
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
		userID, _ := r.Context().Value("userId").(string)
		slog.Info("received request", "path", r.URL.Path, "userId", userID)

		users, err := client.Auth.GetUsers(ctx, userID)
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

		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for destinations list", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		dests, err := dynamicClient.GetDestinations(ctx, pageSize)
		if err != nil {
			slog.Error("failed to get destinations", "err", err)
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
		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for destinations delete", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		// Get all destinations
		// Use a large limit to hopefully get all of them.
		pageSize := 100
		dests, err := dynamicClient.GetDestinations(ctx, pageSize)
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
				if err := dynamicClient.DisableDestination(ctx, d.DestinationID, d.DeliveryConfig.Endpoint, verificationToken); err != nil {
					slog.Error("failed to disable destination", "destinationId", d.DestinationID, "err", err)
				}

				if err := dynamicClient.DeleteDestination(ctx, d.DestinationID); err != nil {
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

		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, sealiftUser, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for subscription create", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, auth.USER, user)
		subID, err := dynamicClient.CreateUserSubscription(ctx, req.TopicID, sealiftUser.DestinationID)
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

		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for subscriptions list", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, auth.USER, user)
		subs, err := dynamicClient.GetUserSubscriptions(ctx)
		if err != nil {
			slog.Error("failed to get subscriptions", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.NotificationSubscriptions{Subscriptions: subs})
	})

	// Delete ALL subscriptions for a seller
	mux.HandleFunc("DELETE /api/notification/users/{user}/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified", http.StatusBadRequest)
			return
		}

		slog.Info("received request to delete all notification subscriptions", "user", user)

		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for subscriptions delete", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, auth.USER, user)
		if err := dynamicClient.DeleteAllUserSubscriptions(ctx); err != nil {
			slog.Error("failed to delete subscriptions", "err", err, "user", user)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	// Enable a subscription for a seller
	mux.HandleFunc("POST /api/notification/users/{user}/subscriptions/enable", func(w http.ResponseWriter, r *http.Request) {
		user := r.PathValue("user")
		if user == "" {
			http.Error(w, "user not specified", http.StatusBadRequest)
			return
		}

		slog.Info("received request to enable subscriptions", "user", user)

		userID, _ := r.Context().Value("userId").(string)
		dynamicClient, _, err := getEbayClientForUser(r.Context(), userID)
		if err != nil {
			slog.Error("Failed to build dynamic client for subscriptions enable", "err", err, "userID", userID)
			http.Error(w, "Failed to resolve credentials", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, auth.USER, user)
		subs, err := dynamicClient.EnableUserSubscriptions(ctx)
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

func newDB(ctx context.Context, uri string) (*mongo.Client, error) {
	if uri == "" {
		return nil, errors.New("empty mongo URI")
	}
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

func sseHandler(inbox *inbox.Receiver, client *ebay.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ebayUser := r.PathValue("user")
		userID, ok := r.Context().Value("userId").(string)
		if !ok || userID == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Verify store ownership
		var check bson.M
		err := client.DB.FindOne(r.Context(), bson.M{"user": ebayUser, "sealift_user_id": userID}).Decode(&check)
		if err != nil {
			slog.Error("Unauthorized SSE attempt", "user", ebayUser, "userId", userID, "err", err)
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		connChan := make(chan map[string]interface{}, 100)
		inbox.AddClient(ebayUser, connChan)
		defer func() {
			inbox.RemoveClient(ebayUser, connChan)
			close(connChan)
		}()

		userWebhooks, _ := inbox.GetPastNotifications(r.Context(), ebayUser)
		if len(userWebhooks) > 0 {
			data, _ := json.Marshal(userWebhooks)
			fmt.Fprintf(w, "event: initial\ndata: %s\n\n", data)
			w.(http.Flusher).Flush()
		}

		for {
			select {
			case msg := <-connChan:
				data, _ := json.Marshal(msg)
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}
}

func notificationHandler(inbox *inbox.Receiver, getClient func(ctx context.Context, userID string) (*ebay.Client, SealiftUser, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.PathValue("tenantID")
		if tenantID == "" {
			http.Error(w, "tenant not specified", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// eBay verification challenge
			challengeCode := r.URL.Query().Get("challenge_code")
			if challengeCode != "" {
				hashInput := challengeCode + verificationToken + endpointURL + "/tenant/" + tenantID
				hash := sha256.Sum256([]byte(hashInput))
				hashString := fmt.Sprintf("%x", hash)
				resp := ChallengeResponse{ChallengeResponse: hashString}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)

		case http.MethodPost:
			reqBody, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}

			// Get tenant's cryptographic keys to verify signature
			client, _, err := getClient(r.Context(), tenantID)
			if err != nil {
				slog.Error("Webhook failed: Tenant client not found", "tenantID", tenantID)
				http.Error(w, "Unauthorized Tenant", http.StatusUnauthorized)
				return
			}

			if err := verifyEbaySignature(r, reqBody, client); err != nil {
				slog.Error("Webhook signature validation failed", "err", err, "tenantID", tenantID)
				http.Error(w, "Invalid Signature", http.StatusPreconditionFailed)
				return
			}

			var payload ebay.NotificationPayload
			if err := json.Unmarshal(reqBody, &payload); err != nil {
				slog.Error("failed to decode payload", "err", err)
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			// Route to the correct eBay store's inbox
			ebayUser := payload.Notification.Data.SenderUserName
			if ebayUser == "" {
				slog.Error("Webhook error: missing sender username in payload")
				http.Error(w, "Missing Sender", http.StatusBadRequest)
				return
			}

			var notif map[string]interface{}
			json.Unmarshal(reqBody, &notif)
			inbox.PushNotification(r.Context(), ebayUser, notif)

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func deletionNotificationHandler(w http.ResponseWriter, r *http.Request, client *ebay.Client) {
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
		// read raw body for signature verification
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// actively check for webhook spoofing!
		if err := verifyEbaySignature(r, reqBody, client); err != nil {
			slog.Error("Webhook signature validation failed", "err", err, "path", r.URL.Path)
			http.Error(w, "Precondition Failed: Invalid Signature", http.StatusPreconditionFailed)
			return
		}

		// handle deletion notification
		var notif map[string]interface{}
		if err := json.Unmarshal(reqBody, &notif); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		slog.Info("received verification-passed deletion notification", "notif", notif)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

var (
	ebayKeyCache = make(map[string]interface{})
	ebayKeyMutex sync.RWMutex
)

// verifyEbaySignature actively checks the X-Ebay-Signature header to ensure webhooks originated from eBay
func verifyEbaySignature(r *http.Request, reqBody []byte, client *ebay.Client) error {
	signatureHeader := r.Header.Get("X-Ebay-Signature")
	if signatureHeader == "" {
		return errors.New("missing X-Ebay-Signature header")
	}

	decodedHeader, err := base64.StdEncoding.DecodeString(signatureHeader)
	if err != nil {
		return fmt.Errorf("invalid base64 signature header: %v", err)
	}

	var sigData struct {
		Alg       string `json:"alg"`
		Kid       string `json:"kid"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(decodedHeader, &sigData); err != nil {
		return fmt.Errorf("failed to parse signature JSON: %v", err)
	}

	if sigData.Kid == "" || sigData.Signature == "" {
		return errors.New("missing kid or signature in X-Ebay-Signature")
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(sigData.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature payload: %v", err)
	}

	// 1. Check Memory Cache for Public Key
	ebayKeyMutex.RLock()
	pubKey, exists := ebayKeyCache[sigData.Kid]
	ebayKeyMutex.RUnlock()

	// 2. Fetch Public Key if missing
	if !exists {
		// Use empty context without User context because public keys are an App-level endpoint.
		pubKeyResp, err := client.GetPublicKey(context.Background(), sigData.Kid)
		if err != nil {
			return fmt.Errorf("failed to fetch public key %s from ebay: %v", sigData.Kid, err)
		}

		block, _ := pem.Decode([]byte(pubKeyResp.Key))
		if block == nil {
			return errors.New("failed to decode PEM block containing public key")
		}

		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}

		// Cache it
		ebayKeyMutex.Lock()
		ebayKeyCache[sigData.Kid] = parsedKey
		pubKey = parsedKey
		ebayKeyMutex.Unlock()
		slog.Info("Successfully cached new eBay Public Key", "kid", sigData.Kid)
	}

	// 3. Cryptographically Verify Signature
	// eBay supports ECDSA, ED25519, and RSA
	switch pub := pubKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, reqBody, decodedSignature) {
			return errors.New("Ed25519 signature verification failed")
		}
	case *ecdsa.PublicKey:
		// Convert to SHA256 sum for ECDSA
		hash := sha256.Sum256(reqBody)
		if !ecdsa.VerifyASN1(pub, hash[:], decodedSignature) {
			return errors.New("ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		// Convert to SHA256 sum for RSA
		hash := sha256.Sum256(reqBody)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], decodedSignature); err != nil {
			return fmt.Errorf("RSA signature verification failed: %v", err)
		}
	default:
		return fmt.Errorf("unknown key type in cache for kid %s", sigData.Kid)
	}

	return nil
}
func getOllamaEmbedding(text string) ([]float32, error) {
	baseUrl := ollamaURL
	if baseUrl == "" {
		baseUrl = "http://localhost:11434"
	}
	url := fmt.Sprintf("%s/api/embeddings", baseUrl)
	payload := map[string]interface{}{
		"model":  "nomic-embed-text",
		"prompt": text,
	}

	body, _ := json.Marshal(payload)

	// Create client with timeout specifically for Ollama
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var result struct {
		Embedding []float32 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Embedding, nil
}

func getCompletion(query string, contextText string, isCasual bool) (string, error) {
	var prompt string
	if isCasual {
		prompt = fmt.Sprintf("The user said: '%s'. No specific documentation context was found. Reply as a friendly assistant for Sealift, providing a greeting and asking how you can help.", query)
	} else {
		prompt = fmt.Sprintf(`You are a helpful AI assistant for the Sealift application. 
Use the following pieces of retrieved documentation context to answer the user's question. 
If you don't know the answer, just say that you don't know, don't try to make up an answer.

Context:
%s

Question: %s

Answer:`, contextText, query)
	}

	cloudKey := os.Getenv("OPENAI_API_KEY")
	if cloudKey != "" {
		baseURL := os.Getenv("OPENAI_BASE_URL")
		if baseURL == "" {
			baseURL = "https://api.groq.com/openai/v1/chat/completions" // Groq cloud is extremely fast & has a free tier for Llama 3
		}
		model := os.Getenv("AI_MODEL")
		if model == "" {
			return "", errors.New("AI_MODEL must be explicitly provided when using a Cloud API key")
		}

		payload := map[string]interface{}{
			"model": model,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		body, _ := json.Marshal(payload)

		client := &http.Client{Timeout: 60 * time.Second}
		req, _ := http.NewRequest("POST", baseURL, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+cloudKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyText, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("cloud AI returned status %d: %s", resp.StatusCode, string(bodyText))
		}

		var result struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", err
		}
		if len(result.Choices) > 0 {
			return result.Choices[0].Message.Content, nil
		}
		return "", errors.New("invalid response from cloud AI")
	}

	// Fallback to local Ollama
	baseUrl := ollamaURL
	if baseUrl == "" {
		baseUrl = "http://localhost:11434"
	}
	url := fmt.Sprintf("%s/api/generate", baseUrl)

	payload := map[string]interface{}{
		"model":  "llama3",
		"prompt": prompt,
		"stream": false,
	}

	body, _ := json.Marshal(payload)

	// Custom client with long timeout for generation
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Response, nil
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dotProduct, normA, normB float32
	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dotProduct / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB))))
}
