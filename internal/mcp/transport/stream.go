package transport

import (
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/runtime"
)

// Stream serves MCP over streamable HTTP transport.
type Stream struct {
	handler http.Handler
}

// StreamConfig configures transport-level behaviour for the streamable MCP
// endpoint.
type StreamConfig struct {
	// PublicURL is the externally reachable base URL of this server, e.g.
	// "http://localhost:8181". It is used to build the RFC 9728
	// protected-resource metadata URL advertised in 401 challenges.
	PublicURL string

	// Verifier validates bearer JWTs at the HTTP edge. Required whenever
	// PublicURL is set: every request to /mcp is verified here; on any
	// failure (missing, expired, bad signature, wrong aud/iss) the handler
	// responds 401 with a WWW-Authenticate challenge so spec-compliant MCP
	// clients re-run discovery. On success the verified claims are injected
	// into the request context for the runtime to consume.
	Verifier BearerVerifier

	// DisableLocalhostProtection maps to
	// mcp.StreamableHTTPOptions.DisableLocalhostProtection.
	DisableLocalhostProtection bool

	// Stateless maps to mcp.StreamableHTTPOptions.Stateless.
	Stateless bool
}

// NewStream builds a streamable MCP transport endpoint handler.
//
// cfg.DisableLocalhostProtection turns off the SDK's automatic DNS-rebinding
// (Host-header) check. That protection assumes a loopback-only dev server and
// rejects any request whose Host header is not a loopback name with 403. When
// the server is deployed behind a public hostname (and typically a
// TLS-terminating proxy), it legitimately binds locally while serving a
// non-loopback Host (e.g. kk-mcp.example:8181); leaving the check on rejects
// every real client with "403 Forbidden: invalid Host header". Enable it in
// those deployments; Host trust is then enforced at the edge (TLS/proxy).
func NewStream(core *runtime.Core, cfg StreamConfig) *Stream {
	opts := &mcp.StreamableHTTPOptions{
		DisableLocalhostProtection: cfg.DisableLocalhostProtection,
		Stateless:                  cfg.Stateless,
	}

	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			return core.Server()
		},
		opts,
	)

	return &Stream{handler: streamable}
}

// Handler returns the streamable MCP HTTP handler.
func (s *Stream) Handler() http.Handler {
	return s.handler
}

// RegisterRoutes mounts streamable MCP transport routes to shared mux. When
// cfg.PublicURL is non-empty, the /mcp handler is wrapped in a 401 bearer
// challenge so spec-compliant MCP clients auto-discover the upstream OIDC
// provider via RFC 9728 protected-resource metadata. cfg.Verifier is required
// in that case: bearer JWTs are verified at the edge and rejected with 401
// on any verification failure (expired, bad signature, wrong audience, etc.).
func RegisterRoutes(mux *http.ServeMux, core *runtime.Core, cfg StreamConfig) error {
	if mux == nil {
		return fmt.Errorf("mcp mux is required")
	}

	if core == nil {
		return fmt.Errorf("mcp runtime core is required")
	}

	handler := NewStream(core, cfg).Handler()

	if cfg.PublicURL != "" {
		if cfg.Verifier == nil {
			return fmt.Errorf("bearer verifier is required")
		}

		handler = WithBearerVerification(cfg.PublicURL, cfg.Verifier, handler)
	}

	handler = withRequestLogging(handler)
	mux.Handle("/mcp", handler)

	return nil
}
