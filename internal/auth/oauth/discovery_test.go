package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPDiscoveryClient_Fetch(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"issuer":%q,
			"jwks_uri":"https://issuer.example.com/keys"
		}`, server.URL)
	}))
	defer server.Close()

	client := NewHTTPDiscoveryClient(server.Client(), false)
	configured := server.URL + "/"
	doc, err := client.Fetch(context.Background(), configured)
	if err != nil {
		t.Fatalf("expected discovery success, got error: %v", err)
	}

	if doc.Issuer != configured {
		t.Fatalf("issuer = %q, want configured %q", doc.Issuer, configured)
	}
	if doc.JWKSURI != "https://issuer.example.com/keys" {
		t.Fatalf("jwks_uri = %q", doc.JWKSURI)
	}
}

func TestHTTPDiscoveryClient_FetchRejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer":"https://other.example",
			"jwks_uri":"https://other.example/keys"
		}`))
	}))
	defer server.Close()

	_, err := NewHTTPDiscoveryClient(server.Client(), false).Fetch(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPDiscoveryClient_FetchRejectsNonLoopbackJWKS(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"issuer":%q,
			"jwks_uri":"http://idp.example/keys"
		}`, server.URL)
	}))
	defer server.Close()

	_, err := NewHTTPDiscoveryClient(server.Client(), false).Fetch(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "allow_http is false") {
		t.Fatalf("error = %v", err)
	}
}
