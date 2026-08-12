package secrets

import (
	"os"
	"strings"
	"testing"
)

func withKeys(t *testing.T, primary, previous string) {
	t.Helper()
	t.Setenv("CREDENTIAL_ENCRYPTION_KEY", primary)
	t.Setenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS", previous)
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	withKeys(t, strings.Repeat("ab", 32), "")
	sealed, err := Encrypt("super-secret-cert")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, prefixV1) {
		t.Fatalf("missing prefix: %q", sealed)
	}
	plain, err := Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "super-secret-cert" {
		t.Fatalf("got %q", plain)
	}
}

func TestNonceUniqueness(t *testing.T) {
	withKeys(t, strings.Repeat("cd", 32), "")
	a, _ := Encrypt("same")
	b, _ := Encrypt("same")
	if a == b {
		t.Fatal("expected unique nonces")
	}
}

func TestLegacyPassthrough(t *testing.T) {
	withKeys(t, strings.Repeat("ef", 32), "")
	plain, err := Decrypt("SBX-plain-cert")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "SBX-plain-cert" {
		t.Fatalf("got %q", plain)
	}
}

func TestTamperDetection(t *testing.T) {
	withKeys(t, strings.Repeat("11", 32), "")
	sealed, _ := Encrypt("cert")
	// Flip a character in the payload.
	raw := []byte(sealed)
	raw[len(raw)-2] ^= 0x01
	if _, err := Decrypt(string(raw)); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	withKeys(t, strings.Repeat("22", 32), "")
	sealed, _ := Encrypt("cert")
	withKeys(t, strings.Repeat("33", 32), "")
	if _, err := Decrypt(sealed); err == nil {
		t.Fatal("expected wrong-key failure")
	}
}

func TestRotation(t *testing.T) {
	old := strings.Repeat("44", 32)
	newKey := strings.Repeat("55", 32)
	withKeys(t, old, "")
	sealed, _ := Encrypt("rotating")
	withKeys(t, newKey, old)
	plain, err := Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "rotating" {
		t.Fatalf("got %q", plain)
	}
}

func TestKeylessCiphertextRefused(t *testing.T) {
	withKeys(t, strings.Repeat("66", 32), "")
	sealed, _ := Encrypt("cert")
	os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY")
	os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS")
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(sealed); err == nil {
		t.Fatal("expected refusal without key")
	}
}

func TestKeylessPlaintextOK(t *testing.T) {
	os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY")
	os.Unsetenv("CREDENTIAL_ENCRYPTION_KEY_PREVIOUS")
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	out, err := Encrypt("plain")
	if err != nil || out != "plain" {
		t.Fatalf("encrypt=%q err=%v", out, err)
	}
	out, err = Decrypt("plain")
	if err != nil || out != "plain" {
		t.Fatalf("decrypt=%q err=%v", out, err)
	}
}
