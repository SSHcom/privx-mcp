package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth/wellknown"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// BearerVerifier is the minimal contract the edge middleware needs from the
// identity-token verifier. It mirrors oauth.IdentityTokenVerifier so the
// transport package can stay decoupled from the concrete verifier type.
type BearerVerifier interface {
	Verify(ctx context.Context, rawToken string) (*oauth.IdentityClaims, error)
}

// WithBearerVerification wraps an http.Handler with the MCP Authorization
// spec's 401 discovery handshake, enforced at the HTTP edge.
//
// On every request the SDK middleware extracts the bearer token and asks the
// verifier to validate it. The challenge is emitted for any auth failure —
// missing header, non-Bearer scheme, expired token, bad signature, wrong
// audience/issuer — so spec-compliant MCP clients re-run the RFC 9728
// discovery flow and obtain a fresh token.
//
// On successful verification TokenInfo is stored on the request context and
// *oauth.IdentityClaims are injected for the runtime ClaimsSource.
func WithBearerVerification(publicURL string, verifier BearerVerifier, next http.Handler) http.Handler {
	metadataURL := buildProtectedResourceMetadataURL(publicURL)
	require := mcpauth.RequireBearerToken(
		tokenVerifier(verifier),
		&mcpauth.RequireBearerTokenOptions{ResourceMetadataURL: metadataURL},
	)

	return require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info := mcpauth.TokenInfoFromContext(r.Context()); info != nil {
			if claims := oauth.ClaimsFromTokenExtra(info.Extra); claims != nil {
				r = r.WithContext(oauth.ContextWithClaims(r.Context(), claims))
			}
		}

		next.ServeHTTP(w, r)
	}))
}

func tokenVerifier(verifier BearerVerifier) mcpauth.TokenVerifier {
	return func(ctx context.Context, rawToken string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		claims, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			logging.Debug("edge bearer verification failed", "err", err)
			return nil, fmt.Errorf("%w: %w", mcpauth.ErrInvalidToken, err)
		}

		if claims == nil {
			return nil, fmt.Errorf("%w: token validation failed", mcpauth.ErrInvalidToken)
		}

		userID := claims.Subject
		if userID == "" {
			userID = claims.UPN
		}

		exp := expirationFromClaims(claims)
		if exp.IsZero() {
			// JWKS verification already required exp. Stubs and tokens whose
			// exp claim we could not copy still need a non-zero time for the
			// SDK middleware.
			exp = time.Now().Add(time.Hour)
		}

		return &mcpauth.TokenInfo{
			UserID:     userID,
			Expiration: exp,
			Extra:      oauth.IdentityClaimsExtra(claims),
		}, nil
	}
}

func expirationFromClaims(claims *oauth.IdentityClaims) time.Time {
	if claims == nil || claims.RawClaims == nil {
		return time.Time{}
	}

	switch exp := claims.RawClaims["exp"].(type) {
	case float64:
		return time.Unix(int64(exp), 0)
	case int64:
		return time.Unix(exp, 0)
	case json.Number:
		n, err := exp.Int64()
		if err != nil {
			return time.Time{}
		}

		return time.Unix(n, 0)
	default:
		return time.Time{}
	}
}

// buildProtectedResourceMetadataURL derives the RFC 9728 metadata URL from the
// server's public base URL.
func buildProtectedResourceMetadataURL(publicURL string) string {
	return strings.TrimRight(publicURL, "/") + wellknown.ProtectedResourceURL
}
