package auth

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/privx"
	"github.com/pmsshintegration/privx-mcp/internal/config"
)

type connectWithExternalJWTFunc func(context.Context, *config.Config, *oauth.IdentityClaims) (restapi.Connector, string, error)

// Authenticator authenticates MCP calls and returns call-scoped auth context.
//
// Verify happens at the HTTP edge (see internal/mcp/transport); the
// authenticator consumes already-verified claims from the request context and
// turns them into a PrivX-backed AuthContext.
type Authenticator interface {
	Authenticate(ctx context.Context, claims *oauth.IdentityClaims) (*AuthContext, error)
}

// mcpAuthenticator implements the Authenticator interface for MCP runtime calls.
// It maps verified IdP claims to a PrivX connector via privx.ConnectWithExternalJWT.
type mcpAuthenticator struct {
	cfg     *config.Config
	connect connectWithExternalJWTFunc
}

// NewAuthenticator creates an Authenticator for MCP tool calls. Token
// verification is performed at the HTTP edge; the authenticator only consumes
// the verified claims.
func NewAuthenticator(cfg *config.Config) Authenticator {
	return &mcpAuthenticator{
		cfg:     cfg,
		connect: privx.ConnectWithExternalJWT,
	}
}

// Authenticate builds an AuthContext from already-verified identity claims by
// establishing a PrivX connector for the resolved user.
func (a *mcpAuthenticator) Authenticate(ctx context.Context, claims *oauth.IdentityClaims) (*AuthContext, error) {
	if a.cfg == nil {
		return nil, fmt.Errorf("auth config is required")
	}

	if claims == nil {
		return nil, &AuthError{Message: "identity verification failed: no verified identity in request context"}
	}

	connector, username, err := a.connect(ctx, a.cfg, claims)
	if err != nil {
		return nil, fmt.Errorf("privx connection failed: %w", err)
	}

	// Active roles are filled later by auth middleware from the permission
	// engine's session-cached ResolveUserRoles result.
	return &AuthContext{
		Username:  username,
		Roles:     nil,
		Connector: connector,
	}, nil
}
