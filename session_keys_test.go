package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testJWK(key *rsa.PrivateKey, kid string) JWK {
	return JWK{
		Alg: "RS256", Kty: "RSA", Kid: kid, Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func testSessionToken(t *testing.T, key *rsa.PrivateKey, kid string, method jwt.SigningMethod) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"sub": "tenant-id", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if kid != "" {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func allowJWKSRefresh(cache *jwksKeyCache, expire bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.refreshAfter = time.Time{}
	if expire {
		cache.expiresAt = time.Time{}
	}
}

func TestSessionSigningKeysSelectKidAndRS256(t *testing.T) {
	oldKey, currentKey := testSigningKey(t), testSigningKey(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(JWKS{Keys: []JWK{testJWK(oldKey, "old"), testJWK(currentKey, "current")}})
	}))
	defer server.Close()

	var cache jwksKeyCache
	tests := []struct {
		name   string
		kid    string
		key    *rsa.PrivateKey
		method jwt.SigningMethod
		valid  bool
	}{
		{"second key", "current", currentKey, jwt.SigningMethodRS256, true},
		{"first key", "old", oldKey, jwt.SigningMethodRS256, true},
		{"wrong key for kid", "old", currentKey, jwt.SigningMethodRS256, false},
		{"unknown kid", "missing", currentKey, jwt.SigningMethodRS256, false},
		{"missing kid", "", currentKey, jwt.SigningMethodRS256, false},
		{"different RSA algorithm", "current", currentKey, jwt.SigningMethodRS512, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := testSessionToken(t, tc.key, tc.kid, tc.method)
			token, err := cache.parseToken(context.Background(), server.URL, raw)
			valid := err == nil && token != nil && token.Valid
			if valid != tc.valid {
				t.Fatalf("valid = %v, want %v (error: %v)", valid, tc.valid, err)
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatalf("JWKS requests = %d, want one cached fetch", calls.Load())
	}
}

func TestSessionSigningKeyRotationSharesConcurrentRefresh(t *testing.T) {
	oldKey, newKey := testSigningKey(t), testSigningKey(t)
	for _, newKid := range []string{"sealift-key-1", "sealift-key-2"} {
		t.Run(newKid, func(t *testing.T) {
			var calls atomic.Int32
			var published atomic.Value
			published.Store(JWKS{Keys: []JWK{testJWK(oldKey, "sealift-key-1")}})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				json.NewEncoder(w).Encode(published.Load())
			}))
			defer server.Close()
			var cache jwksKeyCache

			verifyConcurrently := func(raw string) {
				t.Helper()
				const requests = 32
				start := make(chan struct{})
				errs := make(chan error, requests)
				var wg sync.WaitGroup
				for i := 0; i < requests; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						token, err := cache.parseToken(context.Background(), server.URL, raw)
						if err == nil && !token.Valid {
							err = errors.New("token invalid")
						}
						errs <- err
					}()
				}
				close(start)
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						t.Errorf("concurrent session verification failed: %v", err)
					}
				}
			}

			oldToken := testSessionToken(t, oldKey, "sealift-key-1", jwt.SigningMethodRS256)
			verifyConcurrently(oldToken)
			if calls.Load() != 1 {
				t.Fatalf("cold JWKS requests = %d, want 1", calls.Load())
			}
			published.Store(JWKS{Keys: []JWK{testJWK(newKey, newKid)}})
			allowJWKSRefresh(&cache, false)
			verifyConcurrently(testSessionToken(t, newKey, newKid, jwt.SigningMethodRS256))
			if calls.Load() != 2 {
				t.Fatalf("JWKS requests after rotation = %d, want 2", calls.Load())
			}
			if _, err := cache.parseToken(context.Background(), server.URL, oldToken); err == nil {
				t.Fatal("token signed by removed key is still accepted")
			}
		})
	}
}

func TestSessionSigningKeysExpireAndFailClosed(t *testing.T) {
	key := testSigningKey(t)
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
		json.NewEncoder(w).Encode(JWKS{Keys: []JWK{testJWK(key, "key")}})
	}))
	defer server.Close()
	var cache jwksKeyCache
	raw := testSessionToken(t, key, "key", jwt.SigningMethodRS256)
	if _, err := cache.parseToken(context.Background(), server.URL, raw); err != nil {
		t.Fatal(err)
	}
	allowJWKSRefresh(&cache, true)
	if _, err := cache.parseToken(context.Background(), server.URL, raw); err != nil {
		t.Fatalf("expired cache did not refresh: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	allowJWKSRefresh(&cache, true)
	for i := 0; i < 10; i++ {
		if _, err := cache.parseToken(context.Background(), server.URL, raw); err == nil {
			t.Fatal("expired cache accepted a token after JWKS refresh failed")
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("JWKS requests = %d, want 3 with failed refresh throttled", calls.Load())
	}
}

func TestSessionSigningKeysBoundUntrustedRefreshes(t *testing.T) {
	key, wrongKey := testSigningKey(t), testSigningKey(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(JWKS{Keys: []JWK{testJWK(key, "key")}})
	}))
	defer server.Close()
	var cache jwksKeyCache
	if _, err := cache.parseToken(context.Background(), server.URL,
		testSessionToken(t, key, "key", jwt.SigningMethodRS256)); err != nil {
		t.Fatal(err)
	}
	allowJWKSRefresh(&cache, false)
	invalidSignature := testSessionToken(t, wrongKey, "key", jwt.SigningMethodRS256)
	for i := 0; i < 10; i++ {
		for _, raw := range []string{invalidSignature,
			testSessionToken(t, key, fmt.Sprintf("unknown-%d", i), jwt.SigningMethodRS256)} {
			if _, err := cache.parseToken(context.Background(), server.URL, raw); err == nil {
				t.Fatal("accepted untrusted signing key")
			}
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("JWKS requests = %d, want 2 with untrusted refreshes throttled", calls.Load())
	}
}

func TestFetchSigningKeysRejectMalformedResponses(t *testing.T) {
	key := testJWK(testSigningKey(t), "key")
	tests := []struct {
		name   string
		change func(*JWK)
	}{
		{"empty modulus", func(k *JWK) { k.N = "" }},
		{"zero modulus", func(k *JWK) { k.N = "AA" }},
		{"malformed modulus", func(k *JWK) { k.N = "???" }},
		{"empty exponent", func(k *JWK) { k.E = "" }},
		{"malformed exponent", func(k *JWK) { k.E = "???" }},
		{"even exponent", func(k *JWK) { k.E = "BA" }},
		{"tiny exponent", func(k *JWK) { k.E = "AQ" }},
		{"overflow exponent", func(k *JWK) { k.E = "_____w" }},
		{"oversized exponent", func(k *JWK) { k.E = "AQAAAAE" }},
		{"wrong key type", func(k *JWK) { k.Kty = "EC" }},
		{"wrong algorithm", func(k *JWK) { k.Alg = "RS512" }},
		{"encryption key", func(k *JWK) { k.Use = "enc" }},
		{"missing kid", func(k *JWK) { k.Kid = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			invalid := key
			tc.change(&invalid)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(JWKS{Keys: []JWK{invalid}})
			}))
			defer server.Close()
			if _, err := fetchSigningKeys(context.Background(), server.URL); err == nil {
				t.Fatal("accepted malformed JWKS")
			}
		})
	}
	for name, body := range map[string]string{
		"empty":     `{"keys":[]}`,
		"not json":  `<html>Unavailable</html>`,
		"truncated": `{"keys":[`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			if _, err := fetchSigningKeys(context.Background(), server.URL); err == nil {
				t.Fatal("accepted malformed JWKS response")
			}
		})
	}
	t.Run("duplicate kid", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(JWKS{Keys: []JWK{key, key}})
		}))
		defer server.Close()
		if _, err := fetchSigningKeys(context.Background(), server.URL); err == nil {
			t.Fatal("accepted ambiguous duplicate signing keys")
		}
	})
}

func TestFetchSigningKeysHonorsRequestCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := fetchSigningKeys(ctx, server.URL)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fetch error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("JWKS fetch ignored request cancellation")
	}
}
