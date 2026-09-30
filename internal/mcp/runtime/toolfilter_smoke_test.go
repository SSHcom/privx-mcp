package runtime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

func connectMemoryClient(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(context.Background(), serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session
}

func TestReceivingMiddleware_FiltersToolsOnList(t *testing.T) {
	var filterCalls int
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0.0.0"}, nil)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err != nil || method != methodListTools {
				return result, err
			}

			filterCalls++
			list, ok := result.(*mcp.ListToolsResult)
			if !ok || list == nil {
				return result, nil
			}
			list.Tools = []*mcp.Tool{}
			return list, nil
		}
	})
	server.AddTool(&mcp.Tool{
		Name:        "visible-tool",
		Description: "d",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})

	session := connectMemoryClient(t, server)
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if filterCalls == 0 {
		t.Fatal("expected receiving middleware to run for tools/list")
	}
	if len(listed.Tools) != 0 {
		t.Fatalf("expected filter to remove all tools, got %d", len(listed.Tools))
	}
}

func TestNewCore_WiresToolFilterOnListTools(t *testing.T) {
	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "scoped-tool",
		Description:         "requires hosts-view",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema:         map[string]any{"type": "object"},
	})
	reg.Register(registry.Tool{
		Name:        "public-tool",
		Description: "no requirement",
		InputSchema: map[string]any{"type": "object"},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "0.0.0"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		NewPermissionEngine(),
		stubClaimsSource{}, // no identity → scoped tools must be hidden
	)

	session := connectMemoryClient(t, core.Server())
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	names := make(map[string]struct{}, len(listed.Tools))
	for _, tool := range listed.Tools {
		names[tool.Name] = struct{}{}
	}
	if _, ok := names["scoped-tool"]; ok {
		t.Fatal("expected NewCore-wired tool filter to hide scoped-tool without identity")
	}
	if _, ok := names["public-tool"]; !ok {
		t.Fatal("expected public-tool to remain visible")
	}
}

func TestNewCore_AdvertisesToolsListChanged(t *testing.T) {
	core := NewCore(
		config.ServerConfig{Name: "test", Version: "0.0.0"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		registry.NewRegistry(),
		NewPermissionEngine(),
		stubClaimsSource{},
	)

	session := connectMemoryClient(t, core.Server())
	init := session.InitializeResult()
	if init == nil || init.Capabilities == nil || init.Capabilities.Tools == nil || !init.Capabilities.Tools.ListChanged {
		t.Fatalf("expected tools.listChanged true, got %#v", init)
	}
}
