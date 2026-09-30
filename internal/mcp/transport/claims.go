package transport

import (
	"context"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

// HTTPClaimsSource is the production ClaimsSource implementation. It reads
// claims that the edge middleware injected into the request context. It
// satisfies runtime.ClaimsSource.
type HTTPClaimsSource struct{}

// ToolCallClaims returns the verified claims for a tool call, taken from the
// request context.
func (HTTPClaimsSource) ToolCallClaims(ctx context.Context) *oauth.IdentityClaims {
	return oauth.ClaimsFromContext(ctx)
}

// ListClaims returns the verified claims the edge middleware injected into the
// request context. The same context is used for tools/list and tool calls.
func (HTTPClaimsSource) ListClaims(ctx context.Context) *oauth.IdentityClaims {
	return oauth.ClaimsFromContext(ctx)
}

// MissingClaimsMessage is the client-facing text used when no verified identity
// is present.
func (HTTPClaimsSource) MissingClaimsMessage() string {
	return "authentication required: no verified identity in request context"
}
