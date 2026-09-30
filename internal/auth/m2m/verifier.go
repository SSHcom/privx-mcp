package m2m

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
)

// Issuer is the synthetic issuer placed on claims for a matched service secret.
const Issuer = "privx-mcp-service"

// Verifier accepts a bearer that matches one configured service secret.
type Verifier struct {
	secrets []config.ServiceSecret
}

// NewVerifier returns a verifier for the hashed mappings from config.
func NewVerifier(secrets []config.ServiceSecret) *Verifier {
	return &Verifier{secrets: secrets}
}

// Verify hashes the bearer and compares it to every configured sum.
// Exactly one match succeeds. The secret is not included in errors.
func (v *Verifier) Verify(_ context.Context, raw string) (*oauth.IdentityClaims, error) {
	presented := sha256.Sum256([]byte(raw))
	matched := ""
	hits := 0

	for _, secret := range v.secrets {
		if subtle.ConstantTimeCompare(presented[:], secret.Sum[:]) == 1 {
			hits++
			matched = secret.Username
		}
	}

	if hits != 1 {
		return nil, fmt.Errorf("unknown service secret")
	}

	return &oauth.IdentityClaims{
		Issuer:  Issuer,
		Subject: matched,
		Email:   matched,
		UPN:     matched,
	}, nil
}

// Close is a no-op. The verifier holds no remote resources.
func (v *Verifier) Close() {}
