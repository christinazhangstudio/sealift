package secrets

import (
	"os"
	"strings"
	"testing"
)

func withKey(t *testing.T, key, previous string) {
	t.Helper()
	os.Setenv("CREDENTIAL_ENCRYPTION_KEY", key)
	os.Setenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS", previous)
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	k, _ := NewKey()
	withKey(t, k, "")

	const secret = "PRD-affa7ada50b8-72be-445f-bb4a-e430"
	enc, err := Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(enc) || strings.Contains(enc, secret) {
		t.Fatalf("ciphertext leaks plaintext: %q", enc)
	}
	got, err := Decrypt(enc)
	if err != nil || got != secret {
		t.Fatalf("round trip failed: %q %v", got, err)
	}
}

func TestNonceIsUniquePerCall(t *testing.T) {
	k, _ := NewKey()
	withKey(t, k, "")
	a, _ := Encrypt("same")
	b, _ := Encrypt("same")
	if a == b {
		t.Fatal("identical ciphertext for repeated value — nonce reuse")
	}
}

func TestLegacyPlaintextPassesThrough(t *testing.T) {
	k, _ := NewKey()
	withKey(t, k, "")
	got, err := Decrypt("plaintext-from-before-encryption")
	if err != nil || got != "plaintext-from-before-encryption" {
		t.Fatalf("legacy value not passed through: %q %v", got, err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	k, _ := NewKey()
	withKey(t, k, "")
	enc, _ := Encrypt("sensitive")
	tampered := enc[:len(enc)-4] + "AAAA"
	if _, err := Decrypt(tampered); err == nil {
		t.Fatal("tampered ciphertext decrypted without error")
	}
}

func TestWrongKeyFails(t *testing.T) {
	k1, _ := NewKey()
	withKey(t, k1, "")
	enc, _ := Encrypt("sensitive")

	k2, _ := NewKey()
	withKey(t, k2, "")
	if _, err := Decrypt(enc); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey, _ := NewKey()
	withKey(t, oldKey, "")
	enc, _ := Encrypt("rotate-me")

	newKey, _ := NewKey()
	withKey(t, newKey, oldKey) // new primary, old retained for reads
	got, err := Decrypt(enc)
	if err != nil || got != "rotate-me" {
		t.Fatalf("rotation broke existing values: %q %v", got, err)
	}
}

func TestEncryptedValueUnreadableWithoutKey(t *testing.T) {
	k, _ := NewKey()
	withKey(t, k, "")
	enc, _ := Encrypt("sensitive")

	withKeyless := func() {
		os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY")
		os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS")
		if err := Init(); err != nil {
			t.Fatal(err)
		}
	}
	withKeyless()
	if _, err := Decrypt(enc); err == nil {
		t.Fatal("returned something for an encrypted value with no key")
	}
	if Enabled() {
		t.Fatal("reported enabled with no key")
	}
}

func TestRejectsBadKeyLength(t *testing.T) {
	os.Setenv("CREDENTIAL_ENCRYPTION_KEY", "too-short")
	defer os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY")
	if err := Init(); err == nil {
		t.Fatal("accepted an invalid key")
	}
}
