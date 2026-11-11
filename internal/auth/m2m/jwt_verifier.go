package m2m

import (
	"context"
	"fmt"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/service/jwtcheck"
)

// JWTIssuer is the synthetic issuer placed on claims for a mapped m2m-jwt caller.
const JWTIssuer = "privx-mcp-m2m-jwt"

// JWTVerifier checks expiry and an optional issuer, then maps one claim to a PrivX username.
// It does not verify the JWT signature.
type JWTVerifier struct {
	rows   []config.M2MJWTIdentity
	issuer string
}

// NewJWTVerifier returns a verifier for the configured claim mappings.
func NewJWTVerifier(rows []config.M2MJWTIdentity, issuer string) *JWTVerifier {
	return &JWTVerifier{rows: rows, issuer: issuer}
}

// Verify parses the bearer without checking its signature.
// Exactly one mapping whose claim equals the token value succeeds.
func (v *JWTVerifier) Verify(_ context.Context, raw string) (*oauth.IdentityClaims, error) {
	claims, err := jwtcheck.ParseUnverified(raw)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	if err := jwtcheck.Validate(claims, jwtcheck.Options{ExpectedIssuer: v.issuer}); err != nil {
		return nil, fmt.Errorf("validate token: %w", err)
	}

	username := ""
	hits := 0

	for _, row := range v.rows {
		got, ok := claims[row.Claim].(string)
		if ok && got == row.Value {
			hits++
			username = row.Username
		}
	}

	if hits != 1 {
		return nil, fmt.Errorf("identity mapping matched %d rows", hits)
	}

	rawClaims := make(map[string]any, len(claims))
	for key, value := range claims {
		rawClaims[key] = value
	}

	return &oauth.IdentityClaims{
		Issuer:    JWTIssuer,
		Subject:   username,
		Email:     username,
		UPN:       username,
		RawClaims: rawClaims,
	}, nil
}

// Close is a no-op. The verifier holds no remote resources.
func (v *JWTVerifier) Close() {}

// UsesConfiguredUsername reports issuers whose subject is already the PrivX username.
func UsesConfiguredUsername(issuer string) bool {
	return issuer == Issuer || issuer == JWTIssuer
}
