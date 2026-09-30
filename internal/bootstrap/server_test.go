package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/config"
)

type stubConnector struct{}

func (stubConnector) URL(string, ...interface{}) restapi.CURL { return nil }

// writeKeyFile creates a dummy RSA key file in a temp dir and returns its
// path. resolvePrivXSigningKeyFile now verifies the key file exists, so tests
// that exercise the full config-load path must reference a real file.
func writeKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(path, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}
	return path
}

func TestNewHTTPServerComposesSharedRoutes(t *testing.T) {
	originalConnect := connectWithAPICredentials
	connectWithAPICredentials = func(*config.Config) (restapi.Connector, error) {
		return stubConnector{}, nil
	}
	defer func() {
		connectWithAPICredentials = originalConnect
	}()

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksServer.Close()

	keyFile := writeKeyFile(t)
	configPath := filepath.Join(t.TempDir(), "config.toml")
	configBody := fmt.Sprintf(`
[server]
name = "privx-mcp-server"
version = "test"
public_url = "http://127.0.0.1:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "%s"
rsa_key_id = "test-kid"
audience = "privx-mcp-client"
token_issuer = "privx-mcp"
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "oauth-secret"
api_client_id = "api-client-id"
api_client_secret = "api-client-secret"

[permissions]
default_read_only = true
source_type = "AD"

[oauth]
issuer_url = "https://issuer.example.com"
audience = "privx-mcp-client"
scopes = ["openid","profile","email"]
jwks_uri = "%s/jwks"
identity_claim_field = "email"
identity_mapping_rule = "as-is"
`, keyFile, jwksServer.URL)

	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	server, cleanup, err := NewServer(configPath)
	if err != nil {
		t.Fatalf("expected NewHTTPServer success: %v", err)
	}
	if server == nil {
		t.Fatal("expected server")
		return
	}
	if server.Addr == "" {
		t.Fatal("expected server addr")
	}
	if cleanup == nil {
		t.Fatal("expected cleanup callback")
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("expected /mcp route mounted, got %d", rec.Code)
	}

	// /mcp must challenge with 401 + WWW-Authenticate when no bearer is provided
	// so spec-compliant MCP clients can auto-discover the OIDC provider.
	challengeReq := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	challengeRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(challengeRec, challengeReq)
	if challengeRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected /mcp to return 401 when no Authorization header, got %d", challengeRec.Code)
	}
	if got := challengeRec.Header().Get("WWW-Authenticate"); got == "" || !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("expected WWW-Authenticate with resource_metadata, got %q", got)
	} else if !strings.Contains(got, "http://127.0.0.1:8181/.well-known/oauth-protected-resource") {
		t.Fatalf("expected WWW-Authenticate to point at well-known metadata, got %q", got)
	}

	// /.well-known/oauth-protected-resource must serve RFC 9728 metadata.
	wkReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	wkRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(wkRec, wkReq)
	if wkRec.Code != http.StatusOK {
		t.Fatalf("expected well-known metadata 200, got %d", wkRec.Code)
	}
	if ct := wkRec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content-type, got %q", ct)
	}
	var metadata map[string]any
	if err := json.Unmarshal(wkRec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("failed to decode well-known metadata: %v", err)
	}
	if metadata["resource"] != "http://127.0.0.1:8181/mcp" {
		t.Fatalf("unexpected resource in metadata: %#v", metadata["resource"])
	}
	servers, ok := metadata["authorization_servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != "https://issuer.example.com" {
		t.Fatalf("unexpected authorization_servers: %#v", metadata["authorization_servers"])
	}

	// Legacy /oauth/authorize must no longer be mounted.
	oauthReq := httptest.NewRequest(http.MethodGet, "/oauth/authorize", http.NoBody)
	oauthRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(oauthRec, oauthReq)
	if oauthRec.Code != http.StatusNotFound {
		t.Fatalf("expected /oauth/authorize to be unmounted (404), got %d", oauthRec.Code)
	}

	cleanup()
}

func TestNewServer_M2MSkipsOAuth(t *testing.T) {
	originalConnect := connectWithAPICredentials
	connectWithAPICredentials = func(*config.Config) (restapi.Connector, error) {
		return stubConnector{}, nil
	}
	defer func() {
		connectWithAPICredentials = originalConnect
	}()

	keyFile := writeKeyFile(t)
	secret := strings.Repeat("a", 32)
	configPath := filepath.Join(t.TempDir(), "config.toml")
	configBody := fmt.Sprintf(`
[server]
name = "privx-mcp-server"
version = "test"
public_url = "https://127.0.0.1:8181"
auth_mode = "m2m"
service_secrets = "svc-ci %s"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "%s"
rsa_key_id = "test-kid"
audience = "privx-mcp-client"
token_issuer = "privx-mcp"
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "oauth-secret"
api_client_id = "api-client-id"
api_client_secret = "api-client-secret"

[permissions]
default_read_only = true
source_type = "AD"
`, secret, keyFile)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	server, cleanup, err := NewServer(configPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer cleanup()

	noBearer := httptest.NewRecorder()
	server.Handler.ServeHTTP(noBearer, httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody))
	if noBearer.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer: got %d", noBearer.Code)
	}

	unknown := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 32))
	server.Handler.ServeHTTP(unknown, req)
	if unknown.Code != http.StatusUnauthorized {
		t.Fatalf("unknown bearer: got %d", unknown.Code)
	}

	matched := httptest.NewRecorder()
	okReq := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	okReq.Header.Set("Authorization", "Bearer "+secret)
	server.Handler.ServeHTTP(matched, okReq)
	if matched.Code == http.StatusUnauthorized {
		t.Fatalf("matching bearer rejected: %s", matched.Body.String())
	}

	wk := httptest.NewRecorder()
	server.Handler.ServeHTTP(wk, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody))
	if wk.Code != http.StatusNotFound {
		t.Fatalf("well-known: got %d", wk.Code)
	}
}

func TestResolveVerifierEndpoints_ConfiguredURI(t *testing.T) {
	issuer, jwks, err := resolveVerifierEndpoints(
		"https://issuer.example.com",
		"https://issuer.example.com/jwks",
	)
	if err != nil {
		t.Fatalf("resolveVerifierEndpoints: %v", err)
	}
	if issuer != "https://issuer.example.com" {
		t.Fatalf("issuer = %q", issuer)
	}
	if jwks != "https://issuer.example.com/jwks" {
		t.Fatalf("jwks = %q", jwks)
	}
}

func TestDiscoverJWKSURI_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer":"https://issuer.example.com",
			"jwks_uri":"https://issuer.example.com/keys"
		}`))
	}))
	defer server.Close()

	issuer, jwks, err := discoverJWKSURI(server.URL)
	if err != nil {
		t.Fatalf("discoverJWKSURI: %v", err)
	}
	if issuer != "https://issuer.example.com" {
		t.Fatalf("issuer = %q", issuer)
	}
	if jwks != "https://issuer.example.com/keys" {
		t.Fatalf("jwks = %q", jwks)
	}

	resolvedIssuer, resolvedJWKS, err := resolveVerifierEndpoints(server.URL, "")
	if err != nil {
		t.Fatalf("resolveVerifierEndpoints: %v", err)
	}
	if resolvedIssuer != issuer || resolvedJWKS != jwks {
		t.Fatalf("resolved = %q %q", resolvedIssuer, resolvedJWKS)
	}
}

func TestDiscoverJWKSURI_MalformedIssuer(t *testing.T) {
	_, _, err := discoverJWKSURI("")
	if err == nil {
		t.Fatal("expected error for empty issuer")
	}
	if !strings.Contains(err.Error(), "oauth.issuer_url is required") {
		t.Fatalf("got %v", err)
	}

	_, _, err = resolveVerifierEndpoints("", "")
	if err == nil {
		t.Fatal("expected error when issuer and jwks are both empty")
	}
}

func TestDiscoverJWKSURI_DiscoveryFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, _, err := discoverJWKSURI(server.URL)
	if err == nil {
		t.Fatal("expected discovery failure")
	}
	if !strings.Contains(err.Error(), "fetch provider discovery document") {
		t.Fatalf("got %v", err)
	}
}

func TestNewServer_DCRMetadataRewritesIssuerAndOmitsProtectedResourceScopes(t *testing.T) {
	originalConnect := connectWithAPICredentials
	connectWithAPICredentials = func(*config.Config) (restapi.Connector, error) {
		return stubConnector{}, nil
	}
	defer func() {
		connectWithAPICredentials = originalConnect
	}()

	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"issuer":"https://sts.windows.net/test-tenant/",
				"authorization_endpoint":"https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize",
				"token_endpoint":"https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
				"jwks_uri":"` + upstream.URL + `/jwks",
				"scopes_supported":["openid"]
			}`))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	keyFile := writeKeyFile(t)
	configPath := filepath.Join(t.TempDir(), "config-dcr.toml")
	configBody := fmt.Sprintf(`
[server]
name = "privx-mcp-server"
version = "test"
public_url = "https://privxmcp.sshdemo.net:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "%s"
rsa_key_id = "test-kid"
audience = "privx-mcp-client"
token_issuer = "privx-mcp"
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "oauth-secret"
api_client_id = "api-client-id"
api_client_secret = "api-client-secret"

[permissions]
default_read_only = true
source_type = "AD"

[oauth]
issuer_url = "%s"
audience = "https://privxmcp.sshdemo.net:8181/mcp"
scopes = ["openid","profile","email","offline_access"]
identity_claim_field = "email"
identity_mapping_rule = "as-is"
dcr_stub_client_id = "client-id"
dcr_stub_client_secret = "client-secret"
`, keyFile, upstream.URL)

	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	server, cleanup, err := NewServer(configPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer cleanup()

	prReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", http.NoBody)
	prRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(prRec, prReq)
	if prRec.Code != http.StatusOK {
		t.Fatalf("protected-resource status = %d", prRec.Code)
	}

	var prBody map[string]any
	if err := json.Unmarshal(prRec.Body.Bytes(), &prBody); err != nil {
		t.Fatalf("decode protected-resource: %v", err)
	}

	if _, hasScopes := prBody["scopes_supported"]; hasScopes {
		t.Fatalf("protected-resource scopes_supported should be omitted, got %#v", prBody["scopes_supported"])
	}

	asReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", http.NoBody)
	asRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(asRec, asReq)
	if asRec.Code != http.StatusOK {
		t.Fatalf("authorization-server status = %d", asRec.Code)
	}

	var asBody map[string]any
	if err := json.Unmarshal(asRec.Body.Bytes(), &asBody); err != nil {
		t.Fatalf("decode authorization-server metadata: %v", err)
	}

	// Issuer must be PublicURL (RFC 8414 §3.3), not the upstream Entra issuer.
	if asBody["issuer"] != "https://privxmcp.sshdemo.net:8181" {
		t.Fatalf("issuer = %#v", asBody["issuer"])
	}
}
