package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/remote"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/store"
)

func TestMCPHTTP_ProactiveRefreshUsesNewBearer(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     30 * time.Second,
		accept:        "new-at",
	})

	res, err := remote.Connect(context.Background(), remote.Params{
		HTTP:   MCPHTTP(env.http, env.sess),
		MCPURL: env.mcp.URL,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if len(res.ToolNames) != 1 || res.ToolNames[0] != "echo" {
		t.Fatalf("tools = %#v", res.ToolNames)
	}

	if env.tokenPosts.Load() != 1 {
		t.Fatalf("token posts = %d", env.tokenPosts.Load())
	}

	if env.sawOldBearer.Load() {
		t.Fatal("MCP received the old access token")
	}
}

func TestMCPHTTP_UnauthorizedRetriesAfterRefresh(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     time.Hour,
		accept:        "new-at",
	})

	res, err := remote.Connect(context.Background(), remote.Params{
		HTTP:   MCPHTTP(env.http, env.sess),
		MCPURL: env.mcp.URL,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if len(res.ToolNames) != 1 || res.ToolNames[0] != "echo" {
		t.Fatalf("tools = %#v", res.ToolNames)
	}

	if env.tokenPosts.Load() != 1 {
		t.Fatalf("token posts = %d", env.tokenPosts.Load())
	}

	if !env.sawOldBearer.Load() {
		t.Fatal("MCP never saw the still-usable access token")
	}
}

func TestMCPHTTP_SingleFlightOnOverlapping401(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     time.Hour,
		accept:        "new-at",
		delay401:      30 * time.Millisecond,
		delayToken:    80 * time.Millisecond,
	})

	client := MCPHTTP(env.http, env.sess)
	var wg sync.WaitGroup

	errs := make(chan error, 2)

	for range 2 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			resp, err := client.Get(env.mcp.URL)
			if err != nil {
				errs <- err

				return
			}

			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("status %d", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	if env.tokenPosts.Load() != 1 {
		t.Fatalf("token posts = %d", env.tokenPosts.Load())
	}
}

func TestMCPHTTP_OneRetryAfterRefreshStill401(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     time.Hour,
		accept:        "new-at",
		always401:     true,
	})

	resp, err := MCPHTTP(env.http, env.sess).Post(env.mcp.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	if env.tokenPosts.Load() != 1 {
		t.Fatalf("token posts = %d", env.tokenPosts.Load())
	}
}

func TestMCPHTTP_InvalidGrantDeletesTokens(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     time.Hour,
		accept:        "new-at",
		invalidGrant:  true,
	})

	_, err := remote.Connect(context.Background(), remote.Params{
		HTTP:   MCPHTTP(env.http, env.sess),
		MCPURL: env.mcp.URL,
	})
	if err == nil || !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err = %v", err)
	}

	_, loadErr := store.Load(env.dir, env.key)
	if !errors.Is(loadErr, store.ErrNotFound) {
		t.Fatalf("load = %v", loadErr)
	}

	if env.tokenPosts.Load() != 1 {
		t.Fatalf("token posts = %d", env.tokenPosts.Load())
	}
}

func TestMCPHTTP_EphemeralLeavesTokenFile(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     30 * time.Second,
		accept:        "new-at",
		ephemeral:     true,
	})

	_, err := remote.Connect(context.Background(), remote.Params{
		HTTP:   MCPHTTP(env.http, env.sess),
		MCPURL: env.mcp.URL,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	stored, err := store.Load(env.dir, env.key)
	if err != nil {
		t.Fatal(err)
	}

	if stored.AccessToken != "old-at" || stored.RefreshToken != "old-rt" {
		t.Fatalf("stored = %+v", stored)
	}

	if env.sess.AccessToken() != "new-at" {
		t.Fatalf("memory access = %q", env.sess.AccessToken())
	}
}

func TestMCPHTTP_UnauthenticatedDoesNotRefresh(t *testing.T) {
	t.Parallel()

	mcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("unexpected Authorization header")
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(mcpSrv.Close)

	resp, err := MCPHTTP(httpx.NewClient(true), nil).Get(mcpSrv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestMCPHTTP_RefreshPostOmitsMCPBearer(t *testing.T) {
	t.Parallel()

	env := newRefreshEnv(t, refreshOpts{
		initialAccess: "old-at",
		expiresIn:     30 * time.Second,
		accept:        "new-at",
	})

	_, err := remote.Connect(context.Background(), remote.Params{
		HTTP:   MCPHTTP(env.http, env.sess),
		MCPURL: env.mcp.URL,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	if env.tokenSawMCPBearer.Load() {
		t.Fatal("token endpoint received Authorization: Bearer")
	}
}

type refreshOpts struct {
	initialAccess string
	expiresIn     time.Duration
	accept        string
	invalidGrant  bool
	always401     bool
	ephemeral     bool
	delay401      time.Duration
	delayToken    time.Duration
}

type refreshEnv struct {
	refreshOpts
	http              *http.Client
	sess              *Session
	mcp               *httptest.Server
	dir               string
	key               string
	tokenPosts        atomic.Int32
	sawOldBearer      atomic.Bool
	tokenSawMCPBearer atomic.Bool
}

func newRefreshEnv(t *testing.T, cfg refreshOpts) *refreshEnv {
	t.Helper()

	env := &refreshEnv{refreshOpts: cfg}

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.tokenPosts.Add(1)

		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			env.tokenSawMCPBearer.Store(true)
		}

		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if env.delayToken > 0 {
			time.Sleep(env.delayToken)
		}

		if form.Get("grant_type") != "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		if env.invalidGrant {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  env.accept,
			"refresh_token": "new-rt",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	fake := &refreshMCP{
		env: env,
	}
	mcpSrv := httptest.NewServer(fake)
	t.Cleanup(mcpSrv.Close)
	env.mcp = mcpSrv

	dir := t.TempDir()
	cfgFile := testClientConfig()
	cfgFile.MCPURL = mcpSrv.URL
	key := store.Key(cfgFile.MCPURL, mcpSrv.URL, cfgFile.Client.ClientID)
	tok := store.Tokens{
		AccessToken:  env.initialAccess,
		RefreshToken: "old-rt",
		ExpiresAt:    time.Now().Add(env.expiresIn),
	}
	if err := store.Save(dir, key, tok); err != nil {
		t.Fatal(err)
	}

	httpClient := httpx.NewClient(true)
	sess, err := NewSession(SessionParams{
		HTTP:   httpClient,
		Config: cfgFile,
		Discovered: Result{
			Resource:      mcpSrv.URL,
			TokenEndpoint: tokenSrv.URL,
		},
		Tokens:    tok,
		AuthDir:   dir,
		Ephemeral: cfg.ephemeral,
	})
	if err != nil {
		t.Fatal(err)
	}

	env.http = httpClient
	env.sess = sess
	env.dir = dir
	env.key = key

	return env
}

type refreshMCP struct {
	env *refreshEnv
}

type sessionRPC struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
}

func (f *refreshMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if f.env.always401 || auth == "Bearer "+f.env.initialAccess {
		f.env.sawOldBearer.Store(true)
		if f.env.delay401 > 0 {
			time.Sleep(f.env.delay401)
		}

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	if auth != "Bearer "+f.env.accept {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	switch r.Method {
	case http.MethodGet:
		w.WriteHeader(http.StatusOK)

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

	var req sessionRPC
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	switch req.Method {
	case "server/discover":
		writeSessionRPCError(w, req.ID, -32601, "Method not found")
	case "initialize":
		writeSessionRPCResult(w, req.ID, map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fake", "version": "1"},
		})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		writeSessionRPCResult(w, req.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "echo",
					"description": "echo",
					"inputSchema": map[string]any{"type": "object"},
				},
			},
		})
	default:
		writeSessionRPCError(w, req.ID, -32601, "Method not found")
	}
}

func writeSessionRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
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

func writeSessionRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
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
