package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	pkceVerifierBytes = 32
	stateBytes        = 16
)

type pkce struct {
	Verifier  string
	Challenge string
}

func generatePKCE() (pkce, error) {
	buf := make([]byte, pkceVerifierBytes)
	if _, err := rand.Read(buf); err != nil {
		return pkce{}, fmt.Errorf("pkce verifier: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(buf)

	return pkce{
		Verifier:  verifier,
		Challenge: s256Challenge(verifier),
	}, nil
}

func generateState() (string, error) {
	buf := make([]byte, stateBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
