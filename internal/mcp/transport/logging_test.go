package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func TestWithRequestLogging_RejectsOversizedPostBeforeHandler(t *testing.T) {
	called := false
	handler := withRequestLogging(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

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
	}))

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
