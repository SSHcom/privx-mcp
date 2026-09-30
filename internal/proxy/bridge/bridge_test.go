package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/remote"
)

const sessionHeader = "Mcp-Session-Id"

type fakeMCP struct {
	sessioned     bool
	bearer        string
	callAlways404 bool
	rpcCallError  bool
	call401       bool

	mu          sync.Mutex
	valid       map[string]struct{}
	currentID   string
	deletedIDs  []string
	initializes atomic.Int32

	sawListNoSID bool
	sawListSID   bool
	sawCallNoSID bool
	sawCallSID   bool
	deleted      atomic.Bool
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (f *fakeMCP) dropCurrent() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.currentID == "" {
		return
	}

	delete(f.valid, f.currentID)
}

func (f *fakeMCP) currentSessionID() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.currentID
}

func (f *fakeMCP) knownSession(sid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.sessioned {
		return true
	}

	_, ok := f.valid[sid]

	return ok
}

func (f *fakeMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.bearer != "" && r.Header.Get("Authorization") != "Bearer "+f.bearer {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	switch r.Method {
	case http.MethodGet:
		w.WriteHeader(http.StatusMethodNotAllowed)

		return
	case http.MethodDelete:
		sid := r.Header.Get(sessionHeader)

		f.mu.Lock()
		f.deletedIDs = append(f.deletedIDs, sid)
		delete(f.valid, sid)
		f.mu.Unlock()
		f.deleted.Store(true)
		w.WriteHeader(http.StatusOK)

		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	sid := r.Header.Get(sessionHeader)

	switch req.Method {
	case "server/discover":
		writeRPCError(w, req.ID, -32601, "Method not found")
	case "initialize":
		n := f.initializes.Add(1)
		if f.sessioned {
			id := fmt.Sprintf("sess-%d", n)

			f.mu.Lock()
			if f.valid == nil {
				f.valid = map[string]struct{}{}
			}

			f.valid[id] = struct{}{}
			f.currentID = id
			f.mu.Unlock()
			w.Header().Set(sessionHeader, id)
		}

		writeRPCResult(w, req.ID, map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fake", "version": "1"},
		})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		if f.sessioned && !f.knownSession(sid) {
			f.sawListNoSID = true
			w.WriteHeader(http.StatusNotFound)

			return
		}

		if f.sessioned {
			f.sawListSID = true
		}

		writeRPCResult(w, req.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "echo",
					"description": "echo",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"message": map[string]any{"type": "string"},
						},
					},
				},
			},
		})
	case "tools/call":
		if f.call401 {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		if f.sessioned && !f.knownSession(sid) {
			f.sawCallNoSID = true
			w.WriteHeader(http.StatusNotFound)

			return
		}

		if f.callAlways404 {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		if f.sessioned {
			f.sawCallSID = true
		}

		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}

		_ = json.Unmarshal(req.Params, &call)

		text := string(call.Arguments)
		if call.Name != "echo" || f.rpcCallError {
			writeRPCError(w, req.ID, -32601, "Method not found")

			return
		}

		writeRPCResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": text},
			},
		})
	default:
		writeRPCError(w, req.ID, -32601, "Method not found")
	}
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")

	if len(id) == 0 {
		id = []byte("null")
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  result,
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")

	if len(id) == 0 {
		id = []byte("null")
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error":   map[string]any{"code": code, "message": message},
	})
}

func testParams(srv *httptest.Server, token string) remote.Params {
	client := httpx.WithoutTimeout(httpx.NewClient(true))
	if token != "" {
		client = httpx.WithBearer(client, token)
	}

	return remote.Params{
		HTTP:   client,
		MCPURL: srv.URL,
	}
}

func openRemote(t *testing.T, srv *httptest.Server, token string) *mcp.ClientSession {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
	t.Cleanup(cancel)

	session, err := remote.Open(ctx, testParams(srv, token))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { _ = session.Close() })

	return session
}

func connectLocal(t *testing.T, remoteSession *mcp.ClientSession, params remote.Params) (*mcp.ClientSession, *Forwarder) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
	defer cancel()

	f := NewForwarder(remoteSession, params)
	t.Cleanup(func() { _ = f.Close() })

	server, err := NewServer(ctx, f)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

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

	return session, f
}

func TestBridgeListsRemoteTool(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	remoteSession := openRemote(t, srv, "")
	local, _ := connectLocal(t, remoteSession, testParams(srv, ""))

	listed, err := local.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	if len(listed.Tools) != 1 || listed.Tools[0].Name != "echo" {
		t.Fatalf("tools = %#v", listed.Tools)
	}

	info := local.InitializeResult()
	if info == nil || info.ServerInfo == nil {
		t.Fatal("missing serverInfo")
	}

	if info.ServerInfo.Name != "fake (via privx-mcp-proxy)" {
		t.Fatalf("server name = %q", info.ServerInfo.Name)
	}

	if info.ServerInfo.Version != "1" {
		t.Fatalf("server version = %q", info.ServerInfo.Version)
	}
}

func TestBridgeCallToolForwards(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	remoteSession := openRemote(t, srv, "")
	local, _ := connectLocal(t, remoteSession, testParams(srv, ""))

	result, err := local.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "pong"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}

	if result.IsError {
		t.Fatalf("isError = true: %#v", result)
	}

	if len(result.Content) != 1 {
		t.Fatalf("content = %#v", result.Content)
	}

	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "pong") {
		t.Fatalf("content = %#v", result.Content)
	}
}

func TestBridgeSessionedRequiresSessionHeader(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessioned: true}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	remoteSession := openRemote(t, srv, "")
	local, _ := connectLocal(t, remoteSession, testParams(srv, ""))

	if fake.sawListNoSID {
		t.Fatal("tools/list arrived without Mcp-Session-Id")
	}

	if !fake.sawListSID {
		t.Fatal("tools/list did not include Mcp-Session-Id")
	}

	_, err := local.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "sid"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}

	if fake.sawCallNoSID {
		t.Fatal("tools/call arrived without Mcp-Session-Id")
	}

	if !fake.sawCallSID {
		t.Fatal("tools/call did not include Mcp-Session-Id")
	}
}

func TestBridgeOpenFailsWithoutBearer(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{bearer: "secret"}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
	t.Cleanup(cancel)

	_, err := remote.Open(ctx, remote.Params{
		HTTP:   httpx.WithoutTimeout(httpx.NewClient(true)),
		MCPURL: srv.URL,
	})
	if err == nil {
		t.Fatal("error = nil")
	}

	session, err := remote.Open(ctx, remote.Params{
		HTTP:   httpx.WithBearer(httpx.WithoutTimeout(httpx.NewClient(true)), "secret"),
		MCPURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("open with bearer: %v", err)
	}

	t.Cleanup(func() { _ = session.Close() })
}

func TestBridgeCloseDeletesSession(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessioned: true}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
	defer cancel()

	params := testParams(srv, "")
	remoteSession, err := remote.Open(ctx, params)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	local, f := connectLocal(t, remoteSession, params)
	_ = local.Close()

	if err := f.Close(); err != nil {
		t.Fatalf("remote close: %v", err)
	}

	if !fake.deleted.Load() {
		t.Fatal("expected remote DELETE after local session end")
	}
}

func TestRunRejectsNilTransport(t *testing.T) {
	t.Parallel()

	err := Run(context.Background(), nil, remote.Params{}, nil)
	if err == nil || !strings.Contains(err.Error(), "transport") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunUsesIOTransport(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	remoteSession := openRemote(t, srv, "")

	serverReader, clientWriter := io.Pipe()
	clientReader, serverWriter := io.Pipe()

	runErr := make(chan error, 1)

	go func() {
		runErr <- Run(context.Background(), remoteSession, testParams(srv, ""), &mcp.IOTransport{
			Reader: serverReader,
			Writer: serverWriter,
		})
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	local, err := client.Connect(context.Background(), &mcp.IOTransport{
		Reader: clientReader,
		Writer: clientWriter,
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}

	listed, err := local.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	if len(listed.Tools) != 1 || listed.Tools[0].Name != "echo" {
		t.Fatalf("tools = %#v", listed.Tools)
	}

	_ = local.Close()
	_ = clientWriter.Close()
	_ = clientReader.Close()

	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestEnsureInputSchema(t *testing.T) {
	t.Parallel()

	if got := fmt.Sprintf("%s", ensureInputSchema(nil)); got != `{"type":"object"}` {
		t.Fatalf("nil schema = %s", got)
	}
}

func TestBridgeReinitAfterSession404(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessioned: true}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	params := testParams(srv, "")
	remoteSession := openRemote(t, srv, "")
	local, _ := connectLocal(t, remoteSession, params)

	if fake.initializes.Load() != 1 {
		t.Fatalf("initializes = %d, want 1", fake.initializes.Load())
	}

	_, err := local.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	fake.dropCurrent()

	result, err := local.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "after-reinit"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}

	if result.IsError {
		t.Fatalf("isError = true: %#v", result)
	}

	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "after-reinit") {
		t.Fatalf("content = %#v", result.Content)
	}

	if fake.initializes.Load() != 2 {
		t.Fatalf("initializes = %d, want 2", fake.initializes.Load())
	}
}

func TestBridgeReinitRetriesCallToolOnce(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessioned: true, callAlways404: true}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	params := testParams(srv, "")
	remoteSession := openRemote(t, srv, "")
	local, _ := connectLocal(t, remoteSession, params)

	_, err := local.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "once"},
	})
	if err == nil {
		t.Fatal("error = nil")
	}

	if !strings.Contains(err.Error(), "session not found") {
		t.Fatalf("error = %v, want session not found", err)
	}

	if fake.initializes.Load() != 2 {
		t.Fatalf("initializes = %d, want 2", fake.initializes.Load())
	}
}

func TestBridgeReinitSingleFlight(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessioned: true}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	params := testParams(srv, "")
	remoteSession := openRemote(t, srv, "")
	f := NewForwarder(remoteSession, params)
	t.Cleanup(func() { _ = f.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
	defer cancel()

	if _, err := NewServer(ctx, f); err != nil {
		t.Fatalf("new server: %v", err)
	}

	fake.dropCurrent()

	started := make(chan struct{})
	var startOnce sync.Once
	const callers = 2

	errs := make(chan error, callers)

	for range callers {
		go func() {
			startOnce.Do(func() { close(started) })
			<-started

			callCtx, callCancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
			defer callCancel()

			_, err := f.call(callCtx, &mcp.CallToolParams{
				Name:      "echo",
				Arguments: map[string]any{"message": "race"},
			})
			errs <- err
		}()
	}

	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("call: %v", err)
		}
	}

	if fake.initializes.Load() != 2 {
		t.Fatalf("initializes = %d, want 2", fake.initializes.Load())
	}
}

func TestBridgeStatelessErrorsAreNotSessionMissing(t *testing.T) {
	t.Parallel()

	t.Run("jsonrpc", func(t *testing.T) {
		t.Parallel()

		fake := &fakeMCP{rpcCallError: true}
		srv := httptest.NewServer(fake)
		t.Cleanup(srv.Close)

		params := testParams(srv, "")
		remoteSession := openRemote(t, srv, "")
		local, _ := connectLocal(t, remoteSession, params)

		_, err := local.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "echo",
			Arguments: map[string]any{"message": "rpc"},
		})
		if err == nil {
			t.Fatal("error = nil")
		}

		if errors.Is(err, mcp.ErrSessionMissing) {
			t.Fatalf("treated as session missing: %v", err)
		}

		if fake.initializes.Load() != 1 {
			t.Fatalf("initializes = %d, want 1", fake.initializes.Load())
		}
	})

	t.Run("401", func(t *testing.T) {
		t.Parallel()

		fake := &fakeMCP{call401: true}
		srv := httptest.NewServer(fake)
		t.Cleanup(srv.Close)

		params := testParams(srv, "")
		remoteSession := openRemote(t, srv, "")
		local, _ := connectLocal(t, remoteSession, params)

		_, err := local.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "echo",
			Arguments: map[string]any{"message": "unauth"},
		})
		if err == nil {
			t.Fatal("error = nil")
		}

		if errors.Is(err, mcp.ErrSessionMissing) {
			t.Fatalf("treated as session missing: %v", err)
		}

		if fake.initializes.Load() != 1 {
			t.Fatalf("initializes = %d, want 1", fake.initializes.Load())
		}
	})
}

func TestBridgeCloseDeletesReopenedSession(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessioned: true}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	params := testParams(srv, "")
	ctx, cancel := context.WithTimeout(context.Background(), remote.ConnectTimeout)
	defer cancel()

	remoteSession, err := remote.Open(ctx, params)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	f := NewForwarder(remoteSession, params)

	server, err := NewServer(ctx, f)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	if _, err := server.Connect(context.Background(), serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	local, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}

	t.Cleanup(func() { _ = local.Close() })

	firstID := fake.currentSessionID()
	fake.dropCurrent()

	_, err = local.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "reopen-close"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}

	newID := fake.currentSessionID()
	if newID == "" || newID == firstID {
		t.Fatalf("currentID = %q, first = %q", newID, firstID)
	}

	_ = local.Close()

	if err := f.Close(); err != nil {
		t.Fatalf("forwarder close: %v", err)
	}

	fake.mu.Lock()
	deleted := append([]string{}, fake.deletedIDs...)
	fake.mu.Unlock()

	sawNew := false

	for _, id := range deleted {
		if id == firstID {
			t.Fatalf("DELETE used discarded session %q: %v", firstID, deleted)
		}

		if id == newID {
			sawNew = true
		}
	}

	if !sawNew {
		t.Fatalf("expected DELETE of %q, got %v", newID, deleted)
	}
}
