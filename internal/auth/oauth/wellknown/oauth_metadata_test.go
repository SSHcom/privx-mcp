package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuthMetadataRewritesIssuerAndPreservesScopes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://sts.windows.net/test-tenant/",
			"authorization_endpoint": "https://login.microsoftonline.com/test-tenant/oauth2/authorize",
			"token_endpoint":         "https://login.microsoftonline.com/test-tenant/oauth2/token",
			"scopes_supported":       []string{"openid"},
		})
	}))
	defer upstream.Close()

	mux := http.NewServeMux()
	if err := RegisterOAuthMetadata(mux, OAuthMetadataConfig{
		PublicURL:         "https://privxmcp.sshdemo.net:8181",
		UpstreamIssuerURL: upstream.URL,
		Scopes:            []string{"openid", "profile", "email", "offline_access"},
	}); err != nil {
		t.Fatalf("RegisterOAuthMetadata() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, OAuthMetadataURL, http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// The issuer must be rewritten to this server's PublicURL. Spec-compliant
	// MCP clients (RFC 8414 §3.3) require the metadata issuer to match the
	// authorization-server identifier they fetched it from — this server's
	// PublicURL, not the upstream Entra issuer. Preserving the upstream issuer
	// makes the client reject the metadata with an issuer mismatch.
	if got := body["issuer"]; got != "https://privxmcp.sshdemo.net:8181" {
		t.Fatalf("issuer = %#v, want the server PublicURL", got)
	}

	// Configured scopes OVERRIDE the upstream provider's generic
	// scopes_supported, because cfg.Scopes carries the resource API scope the
	// client must request. Upstream sent only ["openid"], but the config here
	// has four scopes, and those must be what is advertised.
	scopes, ok := body["scopes_supported"].([]any)
	if !ok || len(scopes) != 4 {
		t.Fatalf("scopes_supported = %#v, want the 4 configured scopes", body["scopes_supported"])
	}

	if got := body["registration_endpoint"]; got != "https://privxmcp.sshdemo.net:8181/register" {
		t.Fatalf("registration_endpoint = %#v", got)
	}

	methods, ok := body["code_challenge_methods_supported"].([]any)
	if !ok || len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %#v, want [S256]", body["code_challenge_methods_supported"])
	}
}

func TestOAuthMetadataScopesFallbackFromConfig(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://issuer.example.com",
			"authorization_endpoint": "https://issuer.example.com/authorize",
			"token_endpoint":         "https://issuer.example.com/token",
		})
	}))
	defer upstream.Close()

	mux := http.NewServeMux()
	wantScopes := []string{"openid", "profile"}
	if err := RegisterOAuthMetadata(mux, OAuthMetadataConfig{
		PublicURL:         "https://privxmcp.sshdemo.net:8181",
		UpstreamIssuerURL: upstream.URL,
		Scopes:            wantScopes,
	}); err != nil {
		t.Fatalf("RegisterOAuthMetadata() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, OAuthMetadataURL, http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	scopes, ok := body["scopes_supported"].([]any)
	if !ok || len(scopes) != len(wantScopes) || scopes[0] != wantScopes[0] || scopes[1] != wantScopes[1] {
		t.Fatalf("scopes_supported = %#v, want %#v", body["scopes_supported"], wantScopes)
	}
}
