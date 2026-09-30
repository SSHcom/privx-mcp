package privx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateTestKeyPair creates a temporary RSA key pair and writes the private
// key to a PEM file. Returns the private key, public key, and file path.
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test-key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return privateKey, &privateKey.PublicKey, keyFile
}

// generateTestKeyPairPKCS8 creates a PKCS8-encoded PEM key file.
func generateTestKeyPairPKCS8(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 key: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "test-key-pkcs8.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return privateKey, &privateKey.PublicKey, keyFile
}

func TestNewJWTMinter_Success(t *testing.T) {
	_, _, keyFile := generateTestKeyPair(t)

	minter, err := NewJWTMinter(keyFile, "test-kid", "test-issuer", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}
	if minter == nil {
		t.Fatal("expected non-nil minter")
	}
}

func TestNewJWTMinter_PKCS8(t *testing.T) {
	_, _, keyFile := generateTestKeyPairPKCS8(t)

	minter, err := NewJWTMinter(keyFile, "test-kid", "test-issuer", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter with PKCS8 key failed: %v", err)
	}
	if minter == nil {
		t.Fatal("expected non-nil minter")
	}
}

func TestNewJWTMinter_FileNotFound(t *testing.T) {
	_, err := NewJWTMinter("/nonexistent/path/key.pem", "kid", "issuer", "", "plain")
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

func TestNewJWTMinter_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "bad-key.pem")
	if err := os.WriteFile(keyFile, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("failed to write bad key file: %v", err)
	}

	_, err := NewJWTMinter(keyFile, "kid", "issuer", "", "plain")
	if err == nil {
		t.Fatal("expected error for invalid PEM data")
	}
}

func TestMint_HeaderFields(t *testing.T) {
	_, pubKey, keyFile := generateTestKeyPair(t)

	minter, err := NewJWTMinter(keyFile, "my-kid-123", "my-issuer", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}

	tokenStr, err := minter.Mint("alice")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	// Parse with the public key to verify signature
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !token.Valid {
		t.Fatal("token is not valid")
	}

	// Check header
	if alg := token.Header["alg"]; alg != "RS256" {
		t.Errorf("expected alg=RS256, got %v", alg)
	}
	if typ := token.Header["typ"]; typ != "JWT" {
		t.Errorf("expected typ=JWT, got %v", typ)
	}
	if kid := token.Header["kid"]; kid != "my-kid-123" {
		t.Errorf("expected kid=my-kid-123, got %v", kid)
	}
}

func TestMint_PayloadFields_Plain(t *testing.T) {
	_, pubKey, keyFile := generateTestKeyPair(t)

	minter, err := NewJWTMinter(keyFile, "kid1", "privx-mcp", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}

	beforeMint := time.Now()
	tokenStr, err := minter.Mint("bob")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}
	afterMint := time.Now()

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	// sub
	sub, err := claims.GetSubject()
	if err != nil {
		t.Fatalf("failed to get sub: %v", err)
	}
	if sub != "bob" {
		t.Errorf("expected sub=bob, got %v", sub)
	}

	// iss
	iss, err := claims.GetIssuer()
	if err != nil {
		t.Fatalf("failed to get iss: %v", err)
	}
	if iss != "privx-mcp" {
		t.Errorf("expected iss=privx-mcp, got %v", iss)
	}

	// exp - iat = 90s
	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("failed to get exp: %v", err)
	}
	iat, err := claims.GetIssuedAt()
	if err != nil {
		t.Fatalf("failed to get iat: %v", err)
	}
	diff := exp.Sub(iat.Time)
	if diff != 90*time.Second {
		t.Errorf("expected exp-iat=90s, got %v", diff)
	}

	// nbf
	nbf, err := claims.GetNotBefore()
	if err != nil {
		t.Fatalf("failed to get nbf: %v", err)
	}
	if nbf.Time != iat.Time {
		t.Errorf("expected nbf=iat, got nbf=%v iat=%v", nbf.Time, iat.Time)
	}

	// iat is between beforeMint and afterMint
	if iat.Before(beforeMint.Truncate(time.Second)) {
		t.Errorf("iat %v is before mint start %v", iat.Time, beforeMint)
	}
	if iat.After(afterMint.Add(time.Second)) {
		t.Errorf("iat %v is after mint end %v", iat.Time, afterMint)
	}
}

func TestMint_PayloadFields_DN(t *testing.T) {
	_, pubKey, keyFile := generateTestKeyPair(t)

	minter, err := NewJWTMinter(keyFile, "kid1", "privx-mcp", "", "dn")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}

	tokenStr, err := minter.Mint("alice")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}

	sub, err := claims.GetSubject()
	if err != nil {
		t.Fatalf("failed to get sub: %v", err)
	}
	if sub != "CN=alice" {
		t.Errorf("expected sub=CN=alice, got %v", sub)
	}
}

func TestMint_VerifiableWithPublicKey(t *testing.T) {
	_, pubKey, keyFile := generateTestKeyPair(t)

	minter, err := NewJWTMinter(keyFile, "kid1", "issuer", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}

	tokenStr, err := minter.Mint("testuser")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	// Verify with the correct public key
	_, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	// Verify fails with a different key
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate other RSA key: %v", err)
	}
	_, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return &otherKey.PublicKey, nil
	})
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestMint_ExpMinusIat_Is90Seconds(t *testing.T) {
	_, pubKey, keyFile := generateTestKeyPair(t)

	minter, err := NewJWTMinter(keyFile, "kid1", "issuer", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}

	tokenStr, err := minter.Mint("user1")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()

	diff := exp.Sub(iat.Time)
	if diff != 90*time.Second {
		t.Errorf("expected exp-iat=90s, got %v", diff)
	}
}

func TestMint_AudienceClaim(t *testing.T) {
	_, pubKey, keyFile := generateTestKeyPair(t)

	minterWithAud, err := NewJWTMinter(keyFile, "kid1", "issuer", "https://privx.example.com", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}

	tokenStr, err := minterWithAud.Mint("alice")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	// Must skip audience validation since the parser itself would enforce it.
	token, err := jwt.Parse(tokenStr,
		func(token *jwt.Token) (interface{}, error) { return pubKey, nil },
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	aud, err := claims.GetAudience()
	if err != nil || len(aud) == 0 || aud[0] != "https://privx.example.com" {
		t.Errorf("expected aud=https://privx.example.com, got %v (err=%v)", aud, err)
	}

	// Without audience set, aud claim must be absent.
	minterNoAud, err := NewJWTMinter(keyFile, "kid1", "issuer", "", "plain")
	if err != nil {
		t.Fatalf("NewJWTMinter failed: %v", err)
	}
	tokenStrNoAud, err := minterNoAud.Mint("bob")
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}
	tokenNoAud, err := jwt.Parse(tokenStrNoAud,
		func(token *jwt.Token) (interface{}, error) { return pubKey, nil },
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		t.Fatalf("failed to parse token without aud: %v", err)
	}
	claimsNoAud := tokenNoAud.Claims.(jwt.MapClaims)
	if _, exists := claimsNoAud["aud"]; exists {
		t.Error("expected no aud claim when audience is empty")
	}
}
