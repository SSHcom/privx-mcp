package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
)

const sessionHeader = "Mcp-Session-Id"

type fakeMCP struct {
	sessionID    string
	bearer       string
	pages        [][]map[string]any
	sawListNoSID bool
	sawListSID   bool
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
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
		if f.sessionID != "" {
			w.Header().Set(sessionHeader, f.sessionID)
		}

		writeRPCResult(w, req.ID, map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fake", "version": "1"},
		})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		if f.sessionID != "" && sid != f.sessionID {
			f.sawListNoSID = true
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if f.sessionID != "" {
			f.sawListSID = true
		}

		writeRPCResult(w, req.ID, f.listPage(req.Params))
	default:
		writeRPCError(w, req.ID, -32601, "Method not found")
	}
}

func (f *fakeMCP) listPage(params json.RawMessage) map[string]any {
	pages := f.pages
	if len(pages) == 0 {
		pages = [][]map[string]any{
			{
				{
					"name":        "echo",
					"description": "echo",
					"inputSchema": map[string]any{"type": "object"},
				},
			},
		}
	}

	var cursor struct {
		Cursor string `json:"cursor"`
	}

	_ = json.Unmarshal(params, &cursor)

	page := 0
	if cursor.Cursor != "" {
		_, _ = fmt.Sscanf(cursor.Cursor, "p%d", &page)
	}

	if page < 0 || page >= len(pages) {
		return map[string]any{"tools": []map[string]any{}}
	}

	result := map[string]any{"tools": pages[page]}
	if page+1 < len(pages) {
		result["nextCursor"] = fmt.Sprintf("p%d", page+1)
	}

	return result
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

func connectTo(t *testing.T, srv *httptest.Server, token string) (Result, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), ConnectTimeout)
	t.Cleanup(cancel)

	client := httpx.NewClient(true)
	if token != "" {
		client = httpx.WithBearer(client, token)
	}

	return Connect(ctx, Params{
		HTTP:   client,
		MCPURL: srv.URL,
	})
}

func TestConnectStatelessListsTools(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	res, err := connectTo(t, srv, "")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if len(res.ToolNames) != 1 || res.ToolNames[0] != "echo" {
		t.Fatalf("tools = %#v", res.ToolNames)
	}
}

func TestConnectSessionedRequiresSessionHeader(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{sessionID: "sess-1"}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	res, err := connectTo(t, srv, "")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if len(res.ToolNames) != 1 || res.ToolNames[0] != "echo" {
		t.Fatalf("tools = %#v", res.ToolNames)
	}

	if fake.sawListNoSID {
		t.Fatal("tools/list arrived without Mcp-Session-Id")
	}

	if !fake.sawListSID {
		t.Fatal("tools/list did not include Mcp-Session-Id")
	}
}

func TestConnectBearerRequired(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{bearer: "secret"}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	_, err := connectTo(t, srv, "")
	if err == nil {
		t.Fatal("error = nil")
	}

	res, err := connectTo(t, srv, "secret")
	if err != nil {
		t.Fatalf("connect with bearer: %v", err)
	}

	if len(res.ToolNames) != 1 || res.ToolNames[0] != "echo" {
		t.Fatalf("tools = %#v", res.ToolNames)
	}
}

func TestConnectRejectsMissingURL(t *testing.T) {
	t.Parallel()

	_, err := Connect(context.Background(), Params{HTTP: httpx.NewClient(true)})
	if err == nil || !strings.Contains(err.Error(), "mcp url") {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectListsAllPages(t *testing.T) {
	t.Parallel()

	fake := &fakeMCP{
		pages: [][]map[string]any{
			{
				{
					"name":        "alpha",
					"description": "a",
					"inputSchema": map[string]any{"type": "object"},
				},
			},
			{
				{
					"name":        "beta",
					"description": "b",
					"inputSchema": map[string]any{"type": "object"},
				},
			},
		},
	}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	res, err := connectTo(t, srv, "")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if len(res.ToolNames) != 2 || res.ToolNames[0] != "alpha" || res.ToolNames[1] != "beta" {
		t.Fatalf("tools = %#v", res.ToolNames)
	}
}
