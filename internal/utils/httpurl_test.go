package utils

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireHTTPURL(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"https://idp.example/realms/mcp",
		"http://localhost:8080/realms/mcp",
		"http://127.0.0.1:8080/realms/mcp",
		"http://[::1]:8080/realms/mcp",
	}
	for _, raw := range allowed {
		if _, err := RequireHTTPURL(raw, false); err != nil {
			t.Fatalf("RequireHTTPURL(%q) error = %v", raw, err)
		}
	}

	if _, err := RequireHTTPURL("http://idp.example/realms/mcp", false); err == nil || !strings.Contains(err.Error(), "allow_http is false") {
		t.Fatalf("non-loopback http error = %v", err)
	}

	if _, err := RequireHTTPURL("http://idp.example/realms/mcp", true); err != nil {
		t.Fatalf("allowHTTP http error = %v", err)
	}

	if _, err := RequireHTTPURL("file:///tmp/jwks.json", true); err == nil {
		t.Fatal("file URL accepted")
	}
}

func TestNewHTTPClientRejectsNonLoopbackHTTP(t *testing.T) {
	t.Parallel()

	resp, err := NewHTTPClient(false).Get("http://203.0.113.10/token")
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatal("error = nil")
	}

	if !strings.Contains(err.Error(), "allow_http is false") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewHTTPClientAllowsLoopbackHTTP(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewHTTPClient(false).Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestNewHTTPClientRejectsInsecureRedirect(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewHTTPClient(false).Get(srv.URL)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatal("error = nil")
	}

	if !strings.Contains(err.Error(), "allow_http is false") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewHTTPClientRejectsCrossHostRedirect(t *testing.T) {
	t.Parallel()

	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(dest.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewHTTPClient(true).Get(srv.URL)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatal("error = nil")
	}

	if !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("error = %v", err)
	}
}
