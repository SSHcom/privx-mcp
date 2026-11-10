package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	applog "github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func TestWithRequestLogging_RejectsOversizedPostBeforeHandler(t *testing.T) {
	called := false
	handler := withRequestLogging(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}), nil)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.ContentLength = utils.MaxRequestBody + 1
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler ran for an oversized body")
	}

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestWithRequestLogging_ForwardsSmallPostBody(t *testing.T) {
	const payload = `{"jsonrpc":"2.0","method":"tools/list"}`

	var got string
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read forwarded body: %v", err)
		}

		got = string(body)
		w.WriteHeader(http.StatusNoContent)
	}), nil)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	if got != payload {
		t.Fatalf("forwarded body = %q, want %q", got, payload)
	}
}

func TestWithRequestLogging_OmitsSensitiveRequestBodies(t *testing.T) {
	const secret = "checkout-password-value"
	const responseSecret = "response-password-value"
	path := filepath.Join(t.TempDir(), "app.log")
	cleanup, err := applog.Setup(path, "debug")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer cleanup()

	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"target-domain-managed-account-checkout","arguments":{"secret":"` + secret + `"}}}`
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"secret":"`+responseSecret+`"}`)
	}), func(name string) bool {
		return name == "host-list"
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	body := readLog(t, path)
	if strings.Contains(body, secret) || strings.Contains(body, responseSecret) {
		t.Fatalf("debug log included a secret:\n%s", body)
	}
	if !strings.Contains(body, "tools/call") || !strings.Contains(body, "target-domain-managed-account-checkout") {
		t.Fatalf("debug log missing method or tool name:\n%s", body)
	}
	if !strings.Contains(body, "status=") {
		t.Fatalf("debug log missing status:\n%s", body)
	}
}

func TestWithRequestLogging_LogsRequestBodyNotResponse(t *testing.T) {
	const requestMarker = "web-01.example"
	const responseMarker = "response-only-marker"
	path := filepath.Join(t.TempDir(), "app.log")
	cleanup, err := applog.Setup(path, "debug")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer cleanup()

	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"host-list","arguments":{"common_name":"` + requestMarker + `"}}}`
	handler := withRequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"items":["`+responseMarker+`"]}`)
	}), func(name string) bool {
		return name == "host-list"
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(payload))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	body := readLog(t, path)
	if !strings.Contains(body, requestMarker) {
		t.Fatalf("debug log missing request body:\n%s", body)
	}
	if strings.Contains(body, responseMarker) {
		t.Fatalf("debug log included the response body:\n%s", body)
	}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(body)
}
