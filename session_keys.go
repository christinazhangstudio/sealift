package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwksCacheTTL        = 5 * time.Minute
	jwksRefreshInterval = 30 * time.Second
)

var jwksHTTPClient = &http.Client{Timeout: 5 * time.Second}

type JWK struct {
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// jwksKeyCache serializes refreshes so concurrent requests share one fetch.
// The zero value is ready to use. Keys expire even while their signatures
// remain valid, so removing a key from JWKS eventually stops trusting it.
type jwksKeyCache struct {
	mu           sync.Mutex
	sourceURL    string
	keys         map[string]*rsa.PublicKey
	expiresAt    time.Time
	refreshAfter time.Time
}

func (c *jwksKeyCache) parseToken(ctx context.Context, sourceURL, raw string) (*jwt.Token, error) {
	parse := func(refresh bool) (*jwt.Token, error) {
		return jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, errors.New("session token is missing a key id")
			}
			return c.publicKey(ctx, sourceURL, kid, refresh)
		}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	}

	token, err := parse(false)
	if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		// The frontend currently reuses sealift-key-1 during key rotation.
		// Retry with fresh keys on signature failure as well as on a new kid.
		return parse(true)
	}
	return token, err
}

func (c *jwksKeyCache) publicKey(ctx context.Context, sourceURL, kid string, refresh bool) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c.sourceURL != sourceURL {
		c.sourceURL = sourceURL
		c.keys = nil
		c.expiresAt = time.Time{}
		c.refreshAfter = time.Time{}
	}

	now := time.Now()
	expired := !now.Before(c.expiresAt)
	if (expired || refresh || c.keys[kid] == nil) && !now.Before(c.refreshAfter) {
		// Unknown kids and invalid signatures are attacker-controlled. Bound
		// all refresh attempts, including failures, rather than fetching for
		// every rejected request.
		c.refreshAfter = now.Add(jwksRefreshInterval)
		// This fetch serves every waiting request. One disconnected browser
		// must not cancel it and put healthy callers into the retry cooldown.
		// The dedicated HTTP client's timeout still bounds the shared fetch.
		keys, err := fetchSigningKeys(context.WithoutCancel(ctx), sourceURL)
		if err != nil {
			return nil, err
		}
		c.keys = keys
		c.expiresAt = time.Now().Add(jwksCacheTTL)
		expired = false
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if expired {
		return nil, errors.New("session signing keys have expired")
	}
	key := c.keys[kid]
	if key == nil {
		return nil, errors.New("session signing key not found")
	}
	return key, nil
}

func fetchSigningKeys(ctx context.Context, sourceURL string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request; %w", err)
	}
	resp, err := jwksHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS; %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS; %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kid == "" || jwk.Kty != "RSA" ||
			(jwk.Alg != "" && jwk.Alg != "RS256") ||
			(jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		if keys[jwk.Kid] != nil {
			return nil, errors.New("JWKS contains duplicate signing key ids")
		}
		n, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil || len(n) == 0 {
			return nil, errors.New("invalid RSA modulus in JWKS")
		}
		e, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid RSA exponent in JWKS")
		}
		exponent := new(big.Int).SetBytes(e).Int64()
		modulus := new(big.Int).SetBytes(n)
		if modulus.Sign() <= 0 || exponent < 3 || exponent > 1<<31-1 || exponent%2 == 0 {
			return nil, errors.New("invalid RSA public key in JWKS")
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: modulus, E: int(exponent)}
	}
	if len(keys) == 0 {
		return nil, errors.New("no RS256 signing keys found in JWKS")
	}
	return keys, nil
}
