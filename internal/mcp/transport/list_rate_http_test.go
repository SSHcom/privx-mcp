package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/runtime"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
)

func TestToolsListRateLimitHTTPBody(t *testing.T) {
	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:        "host-list",
		Description: "list hosts",
		InputSchema: map[string]any{"type": "object"},
	})

	core := runtime.NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuthenticator{},
		reg,
		runtime.NewPermissionEngine(),
		HTTPClaimsSource{},
		runtime.WithRateLimiter(session.NewRateLimiter(60, 1, 0), "https://privx.example.com"),
	)

	mux := http.NewServeMux()
	err := RegisterRoutes(mux, core, StreamConfig{
		PublicURL: "http://localhost:8181",
		Stateless: true,
		Verifier: &stubVerifier{claims: &oauth.IdentityClaims{
			Issuer:  "https://issuer.example.com",
			Subject: "user-1",
			Email:   "alice@example.com",
		}},
	})
	if err != nil {
		t.Fatalf("routes: %v", err)
	}

	first := postToolsList(t, mux)
	if strings.Contains(first, "Too many requests") {
		t.Fatalf("first list was limited: %s", first)
	}
	if !strings.Contains(first, "host-list") {
		t.Fatalf("first list missing tool: %s", first)
	}

	second := postToolsList(t, mux)
	if !strings.Contains(second, "Too many requests") {
		t.Fatalf("second list did not return the rate-limit message: %s", second)
	}
	if strings.Contains(second, "host-list") {
		t.Fatalf("rate-limited list still contained tools: %s", second)
	}
}

func postToolsList(t *testing.T, handler http.Handler) string {
	t.Helper()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	payload, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return rec.Header().Get("Content-Type") + " " + http.StatusText(rec.Code) + "\n" + string(payload)
}
