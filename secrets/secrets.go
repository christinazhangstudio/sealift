// Package secrets encrypts the credentials Sealift stores on behalf of its
// tenants — eBay client secrets and per-seller OAuth tokens — so that a copy of
// the database is not a copy of everyone's eBay access.
//
// Values are stored as "enc:v1:<base64(nonce||ciphertext)>" using AES-256-GCM,
// which authenticates as well as encrypts: a tampered value fails to decrypt
// rather than silently returning altered data.
//
// Decrypt accepts unprefixed values and returns them unchanged, so records
// written before encryption was introduced keep working and are re-encrypted
// the next time they are written (or by the startup migration).
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
	"os"
	"strings"
)

const prefix = "enc:v1:"

var (
	// primaryKey encrypts new values and decrypts existing ones.
	primaryKey []byte
	// previousKey only decrypts, so a key can be rotated without a flag day:
	// set the new key as primary and the old one here until everything has been
	// rewritten, then drop it.
	previousKey []byte

	// ErrNoKey means an encrypted value was found but no key is configured to
	// read it. Returning an error beats silently handing back ciphertext.
	ErrNoKey = errors.New("value is encrypted but CREDENTIAL_ENCRYPTION_KEY is not set")
)

// Init loads keys from the environment. It is safe to call with no key
// configured: values are then stored as-is, which keeps local development and
// pre-existing deployments working. Enabled reports which mode is active.
func Init() error {
	var err error
	if primaryKey, err = parseKey(os.Getenv("CREDENTIAL_ENCRYPTION_KEY")); err != nil {
		return fmt.Errorf("CREDENTIAL_ENCRYPTION_KEY: %w", err)
	}
	if previousKey, err = parseKey(os.Getenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS")); err != nil {
		return fmt.Errorf("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: %w", err)
	}
	return nil
}

// Enabled reports whether new values will be encrypted.
func Enabled() bool { return len(primaryKey) > 0 }

// parseKey accepts a 32-byte key as either hex or base64.
func parseKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("must be 32 bytes encoded as hex or base64")
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("must be 32 bytes, got %d", len(decoded))
	}
	return decoded, nil
}

// IsEncrypted reports whether a stored value is in encrypted form.
func IsEncrypted(value string) bool { return strings.HasPrefix(value, prefix) }

// Encrypt returns the value in storable form. With no key configured, or for an
// empty value, it returns the input unchanged.
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" || !Enabled() || IsEncrypted(plaintext) {
		return plaintext, nil
	}

	gcm, err := newGCM(primaryKey)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce; %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. Values without the prefix predate encryption and
// are returned unchanged.
func Decrypt(stored string) (string, error) {
	if !IsEncrypted(stored) {
		return stored, nil
	}
	if !Enabled() && previousKey == nil {
		return "", ErrNoKey
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted value; %w", err)
	}

	for _, key := range [][]byte{primaryKey, previousKey} {
		if key == nil {
			continue
		}
		plaintext, err := open(key, raw)
		if err == nil {
			return plaintext, nil
		}
	}
	return "", errors.New("could not decrypt value with any configured key")
}

func open(key, raw []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("encrypted value is too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher; %w", err)
	}
	return cipher.NewGCM(block)
}

// NewKey generates a fresh 32-byte key, hex encoded, for operators setting this
// up for the first time.
func NewKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
