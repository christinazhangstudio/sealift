package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

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

// authMiddleware returns an http.Handler that validates JWT session cookies
// on protected routes before forwarding to the ServeMux.
//
// JWT and NetworkPolicy are used for different purposes: ("who are you ? vs. who can even talk to you?")
// NetworkPolicy blocks a rogue pod from calling your internal API,
// but can't stop an anonymous browser request from hitting /api/payouts/storename
// because it arrives via the Ingress controller, which is whitelisted
// JWT protects all user-facing routes, but
// /api/internal/get-user is skipped in middleware (necessarily since there's no JWT yet during login),
// which means any pod in the cluster can all it.
func (s *Server) authMiddleware() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("incoming request", "method", r.Method, "path", r.URL.Path)

		// Health probes come from the kubelet, which has no session. Answer them
		// before anything else and without logging, so they don't drown the log.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			s.mux.ServeHTTP(w, r)
			return
		}

		// non-API routes don't need auth
		if !strings.HasPrefix(r.URL.Path, "/api/") &&
			!strings.HasPrefix(r.URL.Path, "/sealift-webhook/") {
			s.mux.ServeHTTP(w, r)
			return
		}

		// Skip auth only where a session cannot exist by definition: eBay's
		// webhooks and OAuth callback (which authenticate by signature and
		// single-use state respectively), and the sign-up / sign-out endpoints.
		//
		// /api/internal/* is server-to-server from the Next.js auth flow and
		// must stay unreachable from outside the cluster — see the NetworkPolicy
		// in deploy/ and the deny rule in the frontend's route handlers.
		//
		// /api/ai/* used to be listed here, which let anyone on the internet
		// run inference on (and ingest into) this deployment for free. Guests
		// still reach it: they hold a real signed session token.
		switch {
		case r.URL.Path == "/sealift-webhook",
			strings.HasPrefix(r.URL.Path, "/sealift-webhook/tenant/"),
			r.URL.Path == "/api/revoke",
			r.URL.Path == "/api/register-user",
			r.URL.Path == "/api/request-password-reset",
			r.URL.Path == "/api/reset-password",
			r.URL.Path == "/api/auth-callback",
			strings.HasPrefix(r.URL.Path, "/api/internal/"):
			s.mux.ServeHTTP(w, r)
			return
		}

		// look for the Auth.js cookie
		var tokenString string
		for _, name := range []string{
			"authjs.session-token",          // default local
			"__Secure-authjs.session-token", // secure production
		} {
			if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
				tokenString = cookie.Value
				break
			}
		}

		if tokenString == "" {
			slog.Warn("unauthorized; no authjs cookie found", "path", r.URL.Path)
			http.Error(w, "unauthorized; no session cookie", http.StatusUnauthorized)
			return
		}

		// validate the JWT signature using asymmetric RS256 keys
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return getPublicKey()
		})

		if err != nil || !token.Valid {
			slog.Error("unauthorized; invalid JWT signature", "err", err, "path", r.URL.Path)
			http.Error(w, "unauthorized; invalid JWT", http.StatusUnauthorized)
			return
		}

		// validate database blocklist (stateless revocation)
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			// Unreadable claims means no tenant identity — fail closed rather
			// than serving the request unscoped.
			slog.Warn("unauthorized; unreadable token claims", "path", r.URL.Path)
			http.Error(w, "unauthorized; invalid JWT", http.StatusUnauthorized)
			return
		}

		if jti, ok := claims["jti"].(string); ok && jti != "" {
			var result bson.M
			err := s.revokedTokensCol.FindOne(r.Context(), bson.M{"jti": jti}).Decode(&result)
			switch {
			case err == nil:
				slog.Warn("unauthorized; token is revoked", "jti", jti)
				http.Error(w, "unauthorized; token is revoked", http.StatusUnauthorized)
				return
			case err != mongo.ErrNoDocuments:
				// Still fail closed, but don't tell the user they were logged
				// out — a Mongo blip would otherwise look like a revocation.
				slog.Error("revocation check failed", "err", err, "jti", jti)
				http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		// A token without `sub` has no tenant identity. Reject it rather than
		// letting the request through unscoped — downstream filters treat an
		// empty tenant ID as "match everything".
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			slog.Warn("unauthorized; token has no subject", "path", r.URL.Path)
			http.Error(w, "unauthorized; token has no subject", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "userId", sub))

		s.mux.ServeHTTP(w, r)
	})
}

func getPublicKey() (*rsa.PublicKey, error) {
	if cachedPubKey != nil {
		return cachedPubKey, nil
	}

	// get JWKS from the Next.js frontend
	url := fmt.Sprintf("%s/api/jwks", frontendURL)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
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
