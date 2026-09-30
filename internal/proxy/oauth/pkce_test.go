package oauth

import (
	"encoding/base64"
	"testing"
	"unicode"
)

func TestGeneratePKCE_S256(t *testing.T) {
	t.Parallel()

	pair, err := generatePKCE()
	if err != nil {
		t.Fatal(err)
	}

	if len(pair.Verifier) < 43 || len(pair.Verifier) > 128 {
		t.Fatalf("verifier length %d", len(pair.Verifier))
	}

	for _, r := range pair.Verifier {
		if !pkceRune(r) {
			t.Fatalf("verifier contains %q", r)
		}
	}

	if pair.Challenge != s256Challenge(pair.Verifier) {
		t.Fatal("challenge is not S256 of verifier")
	}

	if _, err := base64.RawURLEncoding.DecodeString(pair.Challenge); err != nil {
		t.Fatalf("challenge encoding: %v", err)
	}
}

func pkceRune(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}

	switch r {
	case '-', '.', '_', '~':
		return true
	default:
		return false
	}
}
