package m2m

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/config"
)

func TestVerifier_MatchAndMiss(t *testing.T) {
	a := strings.Repeat("a", 32)
	b := strings.Repeat("b", 32)
	v := NewVerifier([]config.ServiceSecret{
		{Username: "svc-ci", Sum: sha256.Sum256([]byte(a))},
		{Username: "svc-nightly", Sum: sha256.Sum256([]byte(b))},
	})
	defer v.Close()

	ci, err := v.Verify(context.Background(), a)
	if err != nil {
		t.Fatalf("match svc-ci: %v", err)
	}
	if ci.Issuer != Issuer || ci.Subject != "svc-ci" || ci.Email != "svc-ci" || ci.UPN != "svc-ci" || len(ci.RawClaims) != 0 {
		t.Fatalf("svc-ci claims = %#v", ci)
	}

	nightly, err := v.Verify(context.Background(), b)
	if err != nil {
		t.Fatalf("match svc-nightly: %v", err)
	}
	if nightly.Subject != "svc-nightly" {
		t.Fatalf("subject = %q", nightly.Subject)
	}

	if _, err := v.Verify(context.Background(), strings.Repeat("c", 32)); err == nil {
		t.Fatal("expected miss")
	}

	dup := NewVerifier([]config.ServiceSecret{
		{Username: "one", Sum: sha256.Sum256([]byte(a))},
		{Username: "two", Sum: sha256.Sum256([]byte(a))},
	})
	if _, err := dup.Verify(context.Background(), a); err == nil || !strings.Contains(err.Error(), "unknown service secret") {
		t.Fatalf("two hits: %v", err)
	}
}
