// Package wellknown serves RFC 9728 protected-resource metadata so that
// spec-compliant MCP clients (e.g. Cursor) can auto-discover the upstream
// authorization server protecting the /mcp resource.
package wellknown

import (
	"fmt"
	"net/http"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// ProtectedResourceURL is the RFC 9728 endpoint served by this package.
const ProtectedResourceURL = "/.well-known/oauth-protected-resource"

// ProtectedResourceConfig describes the metadata returned to MCP clients.
type ProtectedResourceConfig struct {
	// Resource is the canonical URL of the protected resource, e.g.
	// "http://localhost:8181/mcp".
	Resource string

	// AuthorizationServers lists the issuer URLs of the authorization
	// servers (OIDC providers) that can mint bearer tokens accepted by
	// this resource. With strict audience enforcement there is exactly
	// one entry: the configured upstream OIDC issuer.
	AuthorizationServers []string

	// Scopes are advertised as scopes_supported (RFC 9728) so MCP clients
	// have a scope hint for their authorization request.
	Scopes []string
}

// RegisterRoutes attaches the RFC 9728 protected-resource metadata
// endpoint to the shared mux.
func RegisterRoutes(mux *http.ServeMux, cfg ProtectedResourceConfig) error {
	if mux == nil {
		return fmt.Errorf("well-known mux is required")
	}

	if cfg.Resource == "" {
		return fmt.Errorf("well-known resource URL is required")
	}

	if len(cfg.AuthorizationServers) == 0 {
		return fmt.Errorf("well-known authorization servers are required")
	}

	mux.Handle(ProtectedResourceURL, mcpauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:             cfg.Resource,
		AuthorizationServers: cfg.AuthorizationServers,
		ScopesSupported:      cfg.Scopes,
	}))

	return nil
}
