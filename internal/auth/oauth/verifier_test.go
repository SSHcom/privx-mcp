package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testJWKSServer creates an HTTP test server that serves a JWKS containing the given RSA public key.
func testJWKSServer(t *testing.T, key *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()

	// Build a minimal JWKS JSON manually
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   encodeBase64URL(key.N.Bytes()),
				"e":   encodeBase64URL(intToBytes(key.E)),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))

	t.Cleanup(func() { server.Close() })
	return server
}

// encodeBase64URL encodes raw bytes as base64url (no padding).
func encodeBase64URL(data []byte) string {
	const base64URLChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(data)*4+2)/3)
	for i := 0; i < len(data); i += 3 {
		var b0, b1, b2 byte
		b0 = data[i]
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}
		result = append(result,
			base64URLChars[(b0>>2)&0x3f],
			base64URLChars[((b0<<4)|(b1>>4))&0x3f],
		)
		if i+1 < len(data) {
			result = append(result, base64URLChars[((b1<<2)|(b2>>6))&0x3f])
		}
		if i+2 < len(data) {
			result = append(result, base64URLChars[b2&0x3f])
		}
	}
	return string(result)
}

// intToBytes converts an int to big-endian bytes.
func intToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}

// signToken creates a signed JWT with the given claims and key.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func TestJWKSTokenVerifier_ValidToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":                "user123",
		"iss":                issuer,
		"aud":                audience,
		"exp":                jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat":                jwt.NewNumericDate(now),
		"email":              "alice@example.com",
		"preferred_username": "alice",
	}
	token := signToken(t, privateKey, kid, claims)

	idpClaims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("expected valid token to be accepted, got error: %v", err)
	}

	if idpClaims.Subject != "user123" {
		t.Errorf("expected subject %q, got %q", "user123", idpClaims.Subject)
	}
	if idpClaims.Email != "alice@example.com" {
		t.Errorf("expected email %q, got %q", "alice@example.com", idpClaims.Email)
	}
	if idpClaims.UPN != "alice" {
		t.Errorf("expected UPN %q, got %q", "alice", idpClaims.UPN)
	}
	if idpClaims.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, idpClaims.Issuer)
	}
	if len(idpClaims.Audience) != 1 || idpClaims.Audience[0] != audience {
		t.Errorf("expected audience %v, got %v", []string{audience}, idpClaims.Audience)
	}
}

func TestJWKSTokenVerifier_MissingSubject(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	cases := []jwt.MapClaims{
		{
			"iss":                issuer,
			"aud":                audience,
			"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
			"iat":                jwt.NewNumericDate(now),
			"preferred_username": "alice",
		},
		{
			"sub":                "   ",
			"iss":                issuer,
			"aud":                audience,
			"exp":                jwt.NewNumericDate(now.Add(time.Hour)),
			"iat":                jwt.NewNumericDate(now),
			"preferred_username": "alice",
		},
	}

	for _, claims := range cases {
		token := signToken(t, privateKey, kid, claims)

		_, err = verifier.Verify(context.Background(), token)
		if err == nil {
			t.Fatal("expected error for token without a subject, got nil")
		}

		var authErr *VerificationError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected *VerificationError, got %T: %v", err, err)
		}
		if authErr.Reason != "missing_subject" {
			t.Errorf("expected reason %q, got %q", "missing_subject", authErr.Reason)
		}
	}
}

func TestJWKSTokenVerifier_MissingIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"aud": audience,
		"exp": jwt.NewNumericDate(now.Add(time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}
	token := signToken(t, privateKey, kid, claims)

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for token without an issuer, got nil")
	}

	var authErr *VerificationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *VerificationError, got %T: %v", err, err)
	}
	if authErr.Reason != "invalid_token" {
		t.Errorf("expected reason %q, got %q", "invalid_token", authErr.Reason)
	}
}

func TestJWKSTokenVerifier_ExpiredToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	past := time.Now().Add(-2 * time.Hour)
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": issuer,
		"aud": audience,
		"exp": jwt.NewNumericDate(past.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(past),
	}
	token := signToken(t, privateKey, kid, claims)

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}

	var authErr *VerificationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *VerificationError, got %T: %v", err, err)
	}
	if authErr.Reason != "expired" {
		t.Errorf("expected reason %q, got %q", "expired", authErr.Reason)
	}
}

func TestJWKSTokenVerifier_WrongAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": issuer,
		"aud": "api://wrong-app",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}
	token := signToken(t, privateKey, kid, claims)

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}

	var authErr *VerificationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *VerificationError, got %T: %v", err, err)
	}
	if authErr.Reason != "wrong_audience" {
		t.Errorf("expected reason %q, got %q", "wrong_audience", authErr.Reason)
	}
}

func TestJWKSTokenVerifier_WrongIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "https://evil-idp.example.com",
		"aud": audience,
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}
	token := signToken(t, privateKey, kid, claims)

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}

	var authErr *VerificationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *VerificationError, got %T: %v", err, err)
	}
	if authErr.Reason != "wrong_issuer" {
		t.Errorf("expected reason %q, got %q", "wrong_issuer", authErr.Reason)
	}
}

func TestJWKSTokenVerifier_InvalidSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate different RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &differentKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": issuer,
		"aud": audience,
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}
	token := signToken(t, privateKey, kid, claims)

	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}

	var authErr *VerificationError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *VerificationError, got %T: %v", err, err)
	}
	if authErr.Reason != "invalid_signature" {
		t.Errorf("expected reason %q, got %q (message: %s)", "invalid_signature", authErr.Reason, authErr.Message)
	}
}

func TestJWKSTokenVerifier_UPNFromUpnClaim(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	jwksServer := testJWKSServer(t, &privateKey.PublicKey, kid)

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          jwksServer.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": issuer,
		"aud": audience,
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
		"upn": "bob@example.com",
	}
	token := signToken(t, privateKey, kid, claims)

	idpClaims, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}

	if idpClaims.UPN != "bob@example.com" {
		t.Errorf("expected UPN %q, got %q", "bob@example.com", idpClaims.UPN)
	}
}

func TestNewJWKSTokenVerifier_MissingConfig(t *testing.T) {
	tests := []struct {
		name   string
		cfg    JWKSTokenVerifierConfig
		errMsg string
	}{
		{
			name:   "missing JWKS URI",
			cfg:    JWKSTokenVerifierConfig{ExpectedIssuer: "x", ExpectedAudience: "y"},
			errMsg: "JWKS URI is required",
		},
		{
			name:   "missing expected issuer",
			cfg:    JWKSTokenVerifierConfig{JWKSURI: "http://x", ExpectedAudience: "y"},
			errMsg: "expected issuer is required",
		},
		{
			name:   "missing expected audience",
			cfg:    JWKSTokenVerifierConfig{JWKSURI: "http://x", ExpectedIssuer: "y"},
			errMsg: "expected audience is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJWKSTokenVerifier(tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.errMsg {
				t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestJWKSTokenVerifier_CachesKeys(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-key-1"
	issuer := "https://test-idp.example.com"
	audience := "api://test-app"

	fetchCount := 0
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   encodeBase64URL(privateKey.N.Bytes()),
				"e":   encodeBase64URL(intToBytes(privateKey.E)),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	verifier, err := NewJWKSTokenVerifier(JWKSTokenVerifierConfig{
		JWKSURI:          server.URL,
		ExpectedIssuer:   issuer,
		ExpectedAudience: audience,
		CacheTTL:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}
	defer verifier.Close()

	initialFetches := fetchCount

	for i := 0; i < 2; i++ {
		now := time.Now()
		claims := jwt.MapClaims{
			"sub": fmt.Sprintf("user%d", i),
			"iss": issuer,
			"aud": audience,
			"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
			"iat": jwt.NewNumericDate(now),
		}
		token := signToken(t, privateKey, kid, claims)

		_, err = verifier.Verify(context.Background(), token)
		if err != nil {
			t.Fatalf("iteration %d: expected valid token, got error: %v", i, err)
		}
	}

	if fetchCount != initialFetches {
		t.Errorf("expected JWKS to be fetched only once (during init), but it was fetched %d times total", fetchCount)
	}
}
