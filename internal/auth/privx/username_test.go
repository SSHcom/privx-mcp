package privx

import (
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/auth/m2m"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
)

func TestUsernameFromClaims_M2MSkipsStripDomain(t *testing.T) {
	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			IdentityClaimField:  "email",
			IdentityMappingRule: "strip-domain",
		},
	}

	got, err := usernameFromClaims(cfg, &oauth.IdentityClaims{
		Issuer:    m2m.Issuer,
		Subject:   "svc-ci@example.com",
		RawClaims: map[string]any{"email": "svc-ci@example.com"},
	})
	if err != nil {
		t.Fatalf("m2m: %v", err)
	}
	if got != "svc-ci@example.com" {
		t.Fatalf("m2m username = %q", got)
	}

	mapped, err := usernameFromClaims(cfg, &oauth.IdentityClaims{
		Issuer:    "https://idp.example.com",
		RawClaims: map[string]any{"email": "svc-ci@example.com"},
	})
	if err != nil {
		t.Fatalf("oauth: %v", err)
	}
	if mapped != "svc-ci" {
		t.Fatalf("oauth username = %q", mapped)
	}

	if _, err := usernameFromClaims(cfg, &oauth.IdentityClaims{Issuer: m2m.Issuer}); err == nil {
		t.Fatal("expected empty subject to fail")
	}
}
