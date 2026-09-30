package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithoutTimeoutClearsTimeout(t *testing.T) {
	t.Parallel()

	base := NewClient(true)
	if base.Timeout == 0 {
		t.Fatal("NewClient timeout is already 0")
	}

	cloned := WithoutTimeout(base)
	if cloned.Timeout != 0 {
		t.Fatalf("timeout = %v, want 0", cloned.Timeout)
	}

	if base.Timeout == 0 {
		t.Fatal("WithoutTimeout mutated the original client")
	}
}

func TestWithBearerSetsHeader(t *testing.T) {
	t.Parallel()

	var got string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client := WithBearer(NewClient(true), "tok-1")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if got != "Bearer tok-1" {
		t.Fatalf("authorization = %q", got)
	}
}

func TestWithBearerSourceReadsEachRequest(t *testing.T) {
	t.Parallel()

	var got []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	token := "tok-a"
	client := WithBearerSource(NewClient(true), staticTokenSource{get: func() string { return token }})

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get 1: %v", err)
	}

	_ = resp.Body.Close()

	token = "tok-b"

	resp, err = client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get 2: %v", err)
	}

	_ = resp.Body.Close()

	if len(got) != 2 || got[0] != "Bearer tok-a" || got[1] != "Bearer tok-b" {
		t.Fatalf("authorization = %#v", got)
	}
}

type staticTokenSource struct {
	get func() string
}

func (s staticTokenSource) AccessToken() string {
	return s.get()
}

func TestWithBearerOmitsEmptyToken(t *testing.T) {
	t.Parallel()

	var got string
	var present bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["Authorization"]
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client := WithBearer(NewClient(true), "  ")
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if present || got != "" {
		t.Fatalf("authorization present=%v value=%q", present, got)
	}
}

func TestNewClientRejectsInsecureRedirect(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	client := NewClient(false)
	resp, err := client.Get(srv.URL)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatal("error = nil")
	}

	if !strings.Contains(err.Error(), "allow_http is false") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewClientAllowsInsecureRedirectWhenEnabled(t *testing.T) {
	t.Parallel()

	var hits int

	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(dest.Close)

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	t.Cleanup(src.Close)

	client := NewClient(true)
	resp, err := client.Get(src.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if hits != 1 {
		t.Fatalf("dest hits = %d", hits)
	}
}
