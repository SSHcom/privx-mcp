// Package bridge serves a local MCP server that forwards tools to a remote session.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/remote"
	"github.com/pmsshintegration/privx-mcp/internal/version"
)

const proxyName = "privx-mcp-proxy"

var proxyVersion = version.MustComponent(version.Proxy, version.ProxyBinary)

// Forwarder owns the current remote ClientSession and can Open again after
// the remote reports a missing streamable session.
type Forwarder struct {
	mu      sync.Mutex
	closed  bool
	session *mcp.ClientSession
	params  remote.Params
}

// NewForwarder takes ownership of session. Close ends whichever session is current.
func NewForwarder(session *mcp.ClientSession, params remote.Params) *Forwarder {
	return &Forwarder{session: session, params: params}
}

// Close closes the current remote session, if any.
func (f *Forwarder) Close() error {
	if f == nil {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed = true
	sess := f.session
	f.session = nil

	if sess == nil {
		return nil
	}

	return sess.Close()
}

// NewServer lists remote tools and returns a local MCP server that forwards
// tools/call through f.
func NewServer(ctx context.Context, f *Forwarder) (*mcp.Server, error) {
	if f == nil {
		return nil, fmt.Errorf("remote session is required")
	}

	session := f.current()
	if session == nil {
		return nil, fmt.Errorf("remote session is required")
	}

	tools, err := remote.ListAllTools(ctx, session)
	if err != nil {
		return nil, err
	}

	server := mcp.NewServer(localImplementation(session), nil)

	for _, tool := range tools {
		if tool == nil || tool.Name == "" {
			continue
		}

		local := *tool
		local.InputSchema = ensureInputSchema(local.InputSchema)
		server.AddTool(&local, f.handleCall)
	}

	return server, nil
}

// Run serves the forwarding server on t until the session ends or ctx is cancelled.
// It closes the current remote session when it returns.
func Run(ctx context.Context, session *mcp.ClientSession, params remote.Params, t mcp.Transport) error {
	if t == nil {
		return fmt.Errorf("transport is required")
	}

	f := NewForwarder(session, params)
	defer func() { _ = f.Close() }()

	listCtx, cancel := context.WithTimeout(ctx, remote.ConnectTimeout)
	server, err := NewServer(listCtx, f)

	cancel()

	if err != nil {
		return err
	}

	return server.Run(ctx, t)
}

func (f *Forwarder) current() *mcp.ClientSession {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.session
}

func (f *Forwarder) handleCall(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := &mcp.CallToolParams{}
	if req != nil && req.Params != nil {
		params.Name = req.Params.Name
		params.Arguments = req.Params.Arguments
	}

	return f.call(ctx, params)
}

func (f *Forwarder) call(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	sess := f.current()
	if sess == nil {
		return nil, fmt.Errorf("remote session is required")
	}

	result, err := sess.CallTool(ctx, params)
	if !errors.Is(err, mcp.ErrSessionMissing) {
		return result, err
	}

	if err := f.reopen(ctx, sess); err != nil {
		return nil, err
	}

	sess = f.current()
	if sess == nil {
		return nil, fmt.Errorf("remote session is required")
	}

	return sess.CallTool(ctx, params)
}

func (f *Forwarder) reopen(ctx context.Context, dead *mcp.ClientSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return fmt.Errorf("remote session is closed")
	}

	if f.session != dead {
		return nil
	}

	_ = dead.Close()
	f.session = nil

	openCtx, cancel := context.WithTimeout(ctx, remote.ConnectTimeout)
	defer cancel()

	next, err := remote.Open(openCtx, f.params)
	if err != nil {
		return err
	}

	f.session = next
	slog.Info("remote mcp session reopened", "mcp_url", f.params.MCPURL)

	return nil
}

func localImplementation(session *mcp.ClientSession) *mcp.Implementation {
	fallback := &mcp.Implementation{Name: proxyName, Version: proxyVersion}
	if session == nil {
		return fallback
	}

	initResult := session.InitializeResult()
	if initResult == nil || initResult.ServerInfo == nil || initResult.ServerInfo.Name == "" {
		return fallback
	}

	serverVersion := initResult.ServerInfo.Version
	if serverVersion == "" {
		serverVersion = proxyVersion
	}

	return &mcp.Implementation{
		Name:    fmt.Sprintf("%s (via %s)", initResult.ServerInfo.Name, proxyName),
		Version: serverVersion,
	}
}

func ensureInputSchema(schema any) any {
	if schema == nil {
		return json.RawMessage(`{"type":"object"}`)
	}

	raw, ok := schema.(json.RawMessage)
	if ok && (len(raw) == 0 || string(raw) == "null") {
		return json.RawMessage(`{"type":"object"}`)
	}

	return schema
}
