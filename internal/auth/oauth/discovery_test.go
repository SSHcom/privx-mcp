package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPDiscoveryClient_Fetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer":"https://issuer.example.com",
			"jwks_uri":"https://issuer.example.com/keys"
		}`))
	}))
	defer server.Close()

	client := NewHTTPDiscoveryClient(server.Client())
	doc, err := client.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected discovery success, got error: %v", err)
	}

	if doc.Issuer != "https://issuer.example.com" {
		t.Fatalf("unexpected issuer: %q", doc.Issuer)
	}
	if doc.JWKSURI == "" {
		t.Fatal("expected discovery jwks_uri to be set")
	}
}
