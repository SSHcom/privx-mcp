package privx

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// JWTMinter creates signed JWTs for PrivX token exchange.
type JWTMinter interface {
	Mint(username string) (string, error)
}

// jwtMinter implements JWTMinter using RS256 signing.
type jwtMinter struct {
	key           *rsa.PrivateKey
	keyID         string
	issuer        string
	audience      string // aud claim; empty means no aud included
	subjectFormat string // "plain" or "dn"
}

// NewJWTMinter creates a new JWTMinter that loads an RSA private key from
// the given PEM file path. audience is included as the aud claim when non-empty.
// It returns an error if the key file cannot be read or parsed.
func NewJWTMinter(keyFile, keyID, issuer, audience, subjectFormat string) (JWTMinter, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA key file %q: %w", keyFile, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from RSA key file %q", keyFile)
	}

	var privateKey *rsa.PrivateKey

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 RSA private key from %q: %w", keyFile, err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key from %q: %w", keyFile, err)
		}

		var ok bool

		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in %q is not an RSA private key", keyFile)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %q", block.Type, keyFile)
	}

	return &jwtMinter{
		key:           privateKey,
		keyID:         keyID,
		issuer:        issuer,
		audience:      audience,
		subjectFormat: subjectFormat,
	}, nil
}

// Mint creates a signed JWT for the given username.
func (m *jwtMinter) Mint(username string) (string, error) {
	now := time.Now()

	sub := m.formatSubject(username)

	claims := jwt.MapClaims{
		"sub": sub,
		"iss": m.issuer,
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(90 * time.Second)),
	}
	if m.audience != "" {
		claims["aud"] = m.audience
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID
	token.Header["typ"] = "JWT"

	signedToken, err := token.SignedString(m.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	audInfo := "(none)"
	if m.audience != "" {
		audInfo = m.audience
	}

	logging.Debug(
		"minted JWT",
		"kid", m.keyID,
		"iss", m.issuer,
		"sub", sub,
		"aud", audInfo,
		"exp", "+90s",
	)

	return signedToken, nil
}

// formatSubject formats the username according to the configured subject format.
func (m *jwtMinter) formatSubject(username string) string {
	switch m.subjectFormat {
	case "dn":
		return "CN=" + username
	default:
		// "plain" or any unrecognized format defaults to plain
		return username
	}
}
