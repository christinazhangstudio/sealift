// Package secrets encrypts tenant eBay credentials and OAuth tokens at rest.
//
// Wire format: "enc:v1:" + base64.StdEncoding(nonce || ciphertext)
// Algorithm: AES-256-GCM. The key is CREDENTIAL_ENCRYPTION_KEY (64 hex chars).
// CREDENTIAL_ENCRYPTION_KEY_PREVIOUS, when set, decrypts only (rotation).
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

const (
	prefixV1   = "enc:v1:"
	nonceSize  = 12
	keyHexLen  = 64 // 32 bytes
)

var (
	mu          sync.RWMutex
	primaryKey  []byte
	previousKey []byte
	configured  bool
)

// Init loads encryption keys from the environment. Safe to call once at startup.
// Missing keys leave the package in passthrough mode for plaintext values, but
// Decrypt still refuses ciphertext it cannot open.
func Init() error {
	primary, err := parseKey(os.Getenv("CREDENTIAL_ENCRYPTION_KEY"))
	if err != nil {
		return fmt.Errorf("CREDENTIAL_ENCRYPTION_KEY: %w", err)
	}
	previous, err := parseKey(os.Getenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS"))
	if err != nil {
		return fmt.Errorf("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: %w", err)
	}
	if previous != nil && primary == nil {
		return errors.New("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS set without CREDENTIAL_ENCRYPTION_KEY")
	}

	mu.Lock()
	defer mu.Unlock()
	primaryKey = primary
	previousKey = previous
	configured = primary != nil
	if configured {
		slog.Info("credential encryption enabled", "rotationKeyConfigured", previous != nil)
	} else {
		slog.Warn("credential encryption disabled; secrets will be stored and returned as plaintext")
	}
	return nil
}

func parseKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) != keyHexLen {
		return nil, fmt.Errorf("want %d hex characters, got %d", keyHexLen, len(raw))
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return key, nil
}

// Encrypt seals plaintext. With no key configured it returns plaintext unchanged.
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	// Already sealed — leave alone so migrations and retries are idempotent.
	if strings.HasPrefix(plaintext, prefixV1) {
		return plaintext, nil
	}

	mu.RLock()
	key := append([]byte(nil), primaryKey...)
	mu.RUnlock()
	if key == nil {
		return plaintext, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, sealed...)
	return prefixV1 + base64.StdEncoding.EncodeToString(payload), nil
}

// Decrypt opens a sealed value. Unprefixed strings pass through unchanged so
// pre-encryption records keep working. Ciphertext that cannot be opened fails
// closed rather than returning garbage to eBay as a client secret.
func Decrypt(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, prefixV1) {
		return value, nil
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefixV1))
	if err != nil {
		return "", fmt.Errorf("malformed ciphertext: %w", err)
	}
	if len(raw) < nonceSize+1 {
		return "", errors.New("malformed ciphertext: too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]

	mu.RLock()
	keys := make([][]byte, 0, 2)
	if primaryKey != nil {
		keys = append(keys, append([]byte(nil), primaryKey...))
	}
	if previousKey != nil {
		keys = append(keys, append([]byte(nil), previousKey...))
	}
	mu.RUnlock()
	if len(keys) == 0 {
		return "", errors.New("ciphertext present but CREDENTIAL_ENCRYPTION_KEY is not configured")
	}

	var lastErr error
	for _, key := range keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			lastErr = err
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			lastErr = err
			continue
		}
		plain, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			lastErr = err
			continue
		}
		return string(plain), nil
	}
	if lastErr == nil {
		lastErr = errors.New("decryption failed")
	}
	return "", fmt.Errorf("failed to decrypt credential: %w", lastErr)
}

// Enabled reports whether a primary encryption key is loaded.
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return configured
}
