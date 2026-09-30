package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type discoveryFixture struct {
	postStatus int
	getStatus  int
	challenge  string // empty = auto quoted resource_metadata at origin well-known
	prm        func(base string) map[string]any
	oidc       map[string]any
	oauthAS    map[string]any
	prmHits    int
}

func startDiscoveryServer(t *testing.T, f *discoveryFixture) *httptest.Server {
	t.Helper()

	var base string

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		status := f.postStatus
		if r.Method == http.MethodGet {
			status = f.getStatus
		} else if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			ch := f.challenge
			if ch == "" {
				ch = fmt.Sprintf(`Bearer resource_metadata=%q`, base+"/.well-known/oauth-protected-resource")
			}

			w.Header().Set("WWW-Authenticate", ch)
		}

		w.WriteHeader(status)
	})
	if f.prm == nil {
		f.prm = defaultPRM
	}

	if f.postStatus == 0 {
		f.postStatus = http.StatusUnauthorized
	}

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		f.prmHits++

		body := f.prm(base)
		if body == nil {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if f.oidc == nil {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.oidc)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if f.oauthAS == nil {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.oauthAS)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL

	if f.oidc == nil && f.oauthAS == nil {
		f.oidc = defaultOIDC(base)
	}

	return srv
}

func defaultPRM(base string) map[string]any {
	return map[string]any{
		"resource":              base + "/mcp",
		"authorization_servers": []string{base},
		"scopes_supported":      []string{"openid", "profile"},
	}
}

func defaultOIDC(base string) map[string]any {
	return map[string]any{
		"issuer":                 base,
		"authorization_endpoint": base + "/authorize",
		"token_endpoint":         base + "/token",
	}
}

func discover(t *testing.T, mcpURL string, scopes []string) (Result, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), DiscoverTimeout)
	t.Cleanup(cancel)

	return Discover(ctx, NewHTTPClient(false), mcpURL, scopes, false)
}

func TestDiscoverPOST401QuotedMetadata(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{}
	srv := startDiscoveryServer(t, f)

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.Unauthenticated {
		t.Fatal("expected oauth discovery, got unauthenticated")
	}

	if got.Resource != srv.URL+"/mcp" {
		t.Fatalf("resource = %q", got.Resource)
	}

	if got.AuthorizationServer != srv.URL {
		t.Fatalf("authorization_server = %q", got.AuthorizationServer)
	}

	if got.AuthorizationEndpoint != srv.URL+"/authorize" {
		t.Fatalf("authorization_endpoint = %q", got.AuthorizationEndpoint)
	}

	if got.TokenEndpoint != srv.URL+"/token" {
		t.Fatalf("token_endpoint = %q", got.TokenEndpoint)
	}

	if strings.Join(got.Scopes, " ") != "openid profile" {
		t.Fatalf("scopes = %#v", got.Scopes)
	}
}

func TestDiscoverPOST405ThenGET401(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{
		postStatus: http.StatusMethodNotAllowed,
		getStatus:  http.StatusUnauthorized,
	}
	srv := startDiscoveryServer(t, f)

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.TokenEndpoint != srv.URL+"/token" {
		t.Fatalf("token_endpoint = %q", got.TokenEndpoint)
	}
}

func TestDiscoverUnauthenticatedSkipsPRM(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{postStatus: http.StatusOK}
	srv := startDiscoveryServer(t, f)

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if !got.Unauthenticated {
		t.Fatalf("Unauthenticated = false, result = %#v", got)
	}

	if f.prmHits != 0 {
		t.Fatalf("protected-resource hits = %d, want 0", f.prmHits)
	}
}

func TestDiscoverFallbackWellKnownWithoutChallenge(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{challenge: "Bearer"}
	srv := startDiscoveryServer(t, f)

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.AuthorizationServer != srv.URL {
		t.Fatalf("authorization_server = %q", got.AuthorizationServer)
	}
}

func TestDiscoverFirstAuthorizationServer(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{}
	srv := startDiscoveryServer(t, f)
	f.prm = func(base string) map[string]any {
		return map[string]any{
			"resource":              base + "/mcp",
			"authorization_servers": []string{base, "https://other.example"},
		}
	}

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.AuthorizationServer != srv.URL {
		t.Fatalf("authorization_server = %q, want first listed", got.AuthorizationServer)
	}
}

func TestDiscoverMissingTokenEndpoint(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{
		oidc: map[string]any{
			"issuer":                 "https://idp.example",
			"authorization_endpoint": "https://idp.example/authorize",
		},
	}
	srv := startDiscoveryServer(t, f)

	_, err := discover(t, srv.URL+"/mcp", nil)
	if err == nil {
		t.Fatal("error = nil")
	}

	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Fatalf("error = %v, want token_endpoint", err)
	}
}

func TestDiscoverRelativeResourceMetadata(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{
		challenge: `Bearer resource_metadata="/.well-known/oauth-protected-resource"`,
	}
	srv := startDiscoveryServer(t, f)

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.Resource != srv.URL+"/mcp" {
		t.Fatalf("resource = %q", got.Resource)
	}
}

func TestDiscoverConfigScopesOverride(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{
		challenge: `Bearer resource_metadata="/.well-known/oauth-protected-resource", scope="openid extra"`,
	}
	srv := startDiscoveryServer(t, f)

	got, err := discover(t, srv.URL+"/mcp", []string{"from-config"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(got.Scopes) != 1 || got.Scopes[0] != "from-config" {
		t.Fatalf("scopes = %#v", got.Scopes)
	}
}

func TestDiscoverUnquotedResourceMetadata(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{}
	srv := startDiscoveryServer(t, f)
	f.challenge = "Bearer resource_metadata=" + srv.URL + "/.well-known/oauth-protected-resource"

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.TokenEndpoint != srv.URL+"/token" {
		t.Fatalf("token_endpoint = %q", got.TokenEndpoint)
	}
}

func TestDiscoverUsesRFC8414WhenOIDCIncomplete(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{
		oidc: map[string]any{
			"issuer":                 "https://idp.example",
			"authorization_endpoint": "https://idp.example/authorize",
		},
	}
	srv := startDiscoveryServer(t, f)
	f.oauthAS = defaultOIDC(srv.URL)

	got, err := discover(t, srv.URL+"/mcp", nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if got.TokenEndpoint != srv.URL+"/token" {
		t.Fatalf("token_endpoint = %q", got.TokenEndpoint)
	}
}

func TestDiscoverNilClient(t *testing.T) {
	t.Parallel()

	_, err := Discover(context.Background(), nil, "https://example.example/mcp", nil, false)
	if err == nil {
		t.Fatal("error = nil")
	}
}

func TestDiscoverProbe500(t *testing.T) {
	t.Parallel()

	f := &discoveryFixture{postStatus: http.StatusInternalServerError}
	srv := startDiscoveryServer(t, f)

	_, err := discover(t, srv.URL+"/mcp", nil)
	if err == nil {
		t.Fatal("error = nil")
	}
}
