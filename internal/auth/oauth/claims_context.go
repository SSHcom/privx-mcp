package oauth

import "context"

// TokenExtraIdentityClaims is the key used when storing *IdentityClaims on
// MCP SDK TokenInfo.Extra so the runtime can recover claims from RequestExtra
// when the HTTP request context does not reach a tool handler.
const TokenExtraIdentityClaims = "identity_claims"

// claimsContextKey is the context key used to carry verified identity claims
// from the HTTP-edge bearer verifier to the transport-agnostic MCP runtime.
//
// The edge middleware (see internal/mcp/transport) verifies the bearer JWT and,
// on success, stores the resulting *IdentityClaims in the request context. The
// runtime's authenticator then reads the claims from context without re-running
// verification, keeping JWT parsing to a single pass per request.
type claimsContextKey struct{}

// ContextWithClaims returns a new context that carries the given verified
// identity claims. If claims is nil the context is returned unchanged so that
// downstream ClaimsFromContext calls observe "no claims" rather than a typed
// nil pointer.
func ContextWithClaims(ctx context.Context, claims *IdentityClaims) context.Context {
	if claims == nil {
		return ctx
	}

	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext returns the verified identity claims previously injected by
// ContextWithClaims, or nil if none are present.
func ClaimsFromContext(ctx context.Context) *IdentityClaims {
	claims, _ := ctx.Value(claimsContextKey{}).(*IdentityClaims)
	return claims
}

// IdentityClaimsExtra puts claims on a TokenInfo.Extra map for the MCP SDK
// bearer middleware.
func IdentityClaimsExtra(claims *IdentityClaims) map[string]any {
	if claims == nil {
		return map[string]any{}
	}

	return map[string]any{TokenExtraIdentityClaims: claims}
}

// ClaimsFromTokenExtra reads *IdentityClaims stored by IdentityClaimsExtra.
func ClaimsFromTokenExtra(extra map[string]any) *IdentityClaims {
	if extra == nil {
		return nil
	}

	claims, _ := extra[TokenExtraIdentityClaims].(*IdentityClaims)

	return claims
}
