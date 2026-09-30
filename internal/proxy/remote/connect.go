// Package remote talks to a remote MCP server over streamable HTTP.
package remote

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/version"
)

// ConnectTimeout is the budget for initialize + tools/list (+ close on --connect).
const ConnectTimeout = 30 * time.Second

// Params is the input to Open and Connect.
type Params struct {
	HTTP    *http.Client
	MCPURL  string
	Name    string
	Version string
}

// Result is a successful smoke connect.
type Result struct {
	ToolNames []string
}

// Open initializes a streamable HTTP MCP session. The caller must Close it.
func Open(ctx context.Context, p Params) (*mcp.ClientSession, error) {
	if p.HTTP == nil {
		return nil, fmt.Errorf("http client is required")
	}

	if p.MCPURL == "" {
		return nil, fmt.Errorf("mcp url is required")
	}

	name := p.Name
	if name == "" {
		name = version.ProxyBinary
	}

	ver := p.Version
	if ver == "" {
		ver = version.MustComponent(version.Proxy, version.ProxyBinary)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: name, Version: ver}, nil)

	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             p.MCPURL,
		HTTPClient:           p.HTTP,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp connect: %w", err)
	}

	return session, nil
}

// Connect initializes a streamable HTTP MCP session, lists all tools, and closes.
func Connect(ctx context.Context, p Params) (Result, error) {
	session, err := Open(ctx, p)
	if err != nil {
		return Result{}, err
	}

	defer func() { _ = session.Close() }()

	tools, err := ListAllTools(ctx, session)
	if err != nil {
		return Result{}, err
	}

	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		if tool == nil || tool.Name == "" {
			continue
		}

		names = append(names, tool.Name)
	}

	return Result{ToolNames: names}, nil
}

// ListAllTools pages through remote tools/list until NextCursor is empty.
func ListAllTools(ctx context.Context, session *mcp.ClientSession) ([]*mcp.Tool, error) {
	if session == nil {
		return nil, fmt.Errorf("remote session is required")
	}

	tools := []*mcp.Tool{}

	var cursor string

	for {
		listed, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}

		if listed != nil {
			tools = append(tools, listed.Tools...)
			if listed.NextCursor == "" || listed.NextCursor == cursor {
				break
			}

			cursor = listed.NextCursor

			continue
		}

		break
	}

	return tools, nil
}
