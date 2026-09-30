package transport

import (
	"context"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

func TestHTTPClaimsSource_ReadsContext(t *testing.T) {
	source := HTTPClaimsSource{}
	ctx := oauth.ContextWithClaims(context.Background(), &oauth.IdentityClaims{Subject: "edge-user"})

	listClaims := source.ListClaims(ctx)
	if listClaims == nil || listClaims.Subject != "edge-user" {
		t.Fatalf("expected edge-user claims from ListClaims, got %+v", listClaims)
	}

	callClaims := source.ToolCallClaims(ctx)
	if callClaims == nil || callClaims.Subject != "edge-user" {
		t.Fatalf("expected edge-user claims from ToolCallClaims, got %+v", callClaims)
	}

	if emptyClaims := source.ListClaims(context.Background()); emptyClaims != nil {
		t.Fatalf("expected nil claims when context has none, got %+v", emptyClaims)
	}
}
