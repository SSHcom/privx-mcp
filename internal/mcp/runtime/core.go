// Package runtime is the transport-agnostic MCP server core.
//
// Request pipeline:
//  1. Transport edge (HTTP): verify Bearer JWT and inject claims into context
//  2. ClaimsSource: read verified identity
//  3. RateLimiter: per-identity tool-call quota (optional), before PrivX login
//  4. Authenticator: exchange identity for a PrivX user connector
//  5. PermissionEngine: evaluate required PrivX scopes / roles
//  6. Tool handler: invoke the registered tool and map errors to MCP results
//
// tools/list uses ClaimsSource + PermissionEngine only (via receiving
// middleware that filters ListToolsResult). tools/call runs the full pipeline
// (via authMiddleware around each tool handler).
package runtime

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
)

const methodListTools = "tools/list"

// ClaimsSource provides transport-specific extraction of verified identity
// claims while the runtime remains transport-agnostic.
//
// ToolCallClaims serves the call-time auth middleware; ListClaims serves the
// list-time tool filter. Transports that inject claims into the request context
// (e.g. HTTPClaimsSource) satisfy both from the context.
type ClaimsSource interface {
	ToolCallClaims(ctx context.Context) *oauth.IdentityClaims
	ListClaims(ctx context.Context) *oauth.IdentityClaims
	MissingClaimsMessage() string
}

// Core is a transport-agnostic MCP runtime. It owns auth, permissions, and tool
// bridging, while transport adapters own wire-specific serving concerns.
type Core struct {
	mcpServer      *mcp.Server
	cfg            config.ServerConfig
	auth           auth.Authenticator
	registry       registry.Registry
	permissions    *PermissionEngine
	claimsSource   ClaimsSource
	rateLimiter    *session.RateLimiter
	sessionBaseURL string
}

// CoreOption configures optional Core behavior.
type CoreOption func(*Core)

// WithRateLimiter attaches a per-identity tool-call rate limiter.
func WithRateLimiter(limiter *session.RateLimiter, baseURL string) CoreOption {
	return func(c *Core) {
		if c == nil {
			return
		}

		c.rateLimiter = limiter
		c.sessionBaseURL = baseURL
	}
}

// NewCore builds the MCP runtime: it wires authentication, the permission
// engine, and the tool registry into a configured MCP server.
func NewCore(
	cfg config.ServerConfig,
	authenticator auth.Authenticator,
	reg registry.Registry,
	permissions *PermissionEngine,
	claimsSource ClaimsSource,
	options ...CoreOption,
) *Core {
	c := &Core{
		cfg:          cfg,
		auth:         authenticator,
		registry:     reg,
		permissions:  permissions,
		claimsSource: claimsSource,
	}

	for _, option := range options {
		if option == nil {
			continue
		}

		option(c)
	}

	c.mcpServer = mcp.NewServer(
		&mcp.Implementation{Name: cfg.Name, Version: cfg.Version},
		&mcp.ServerOptions{
			PageSize: mcp.DefaultPageSize,
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{ListChanged: true},
			},
		},
	)
	c.mcpServer.AddReceivingMiddleware(c.receivingMiddleware)
	c.registerTools()

	return c
}

func (c *Core) registerTools() {
	for _, tool := range c.registry.Tools() {
		c.mcpServer.AddTool(convertTool(tool), c.authMiddleware(c.createToolHandler(tool)))
	}
}

// Server returns the underlying MCP server the transport serves.
func (c *Core) Server() *mcp.Server { return c.mcpServer }

// ServerInfo returns the server name and version as a display string.
func (c *Core) ServerInfo() string { return fmt.Sprintf("%s v%s", c.cfg.Name, c.cfg.Version) }

// receivingMiddleware copies identity claims from the SDK request extra onto
// the handler context, then hides tools the caller is not allowed to invoke
// from tools/list results.
func (c *Core) receivingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		ctx = bindIdentityContext(ctx, req)

		result, err := next(ctx, method, req)
		if err != nil || method != methodListTools {
			return result, err
		}

		list, ok := result.(*mcp.ListToolsResult)
		if !ok || list == nil {
			return result, nil
		}

		list.Tools = c.filterListedTools(ctx, list.Tools)

		return list, nil
	}
}

func bindIdentityContext(ctx context.Context, req mcp.Request) context.Context {
	extra := req.GetExtra()
	if extra == nil || extra.TokenInfo == nil {
		return ctx
	}

	claims := oauth.ClaimsFromTokenExtra(extra.TokenInfo.Extra)
	if claims == nil {
		return ctx
	}

	return oauth.ContextWithClaims(ctx, claims)
}
