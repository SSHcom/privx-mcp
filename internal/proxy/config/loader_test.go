package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_RequiresPath(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Fatal("Load() error = nil, want required path")
	}
}

func TestLoad_FromTOML(t *testing.T) {
	path := writeTOML(t, `
mcp_url = "https://mcp.example.example/mcp"
allow_http = true
log_level = "debug"

[callback]
host = "localhost"
port = 4444
path = "/oauth/callback"
auth_timeout_seconds = 30

[client]
client_id = "proxy"
client_secret = "s3cret"
scopes = ["mcp"]
token_endpoint_auth_method = "client_secret_post"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.MCPURL != "https://mcp.example.example/mcp" {
		t.Errorf("MCPURL = %q", cfg.MCPURL)
	}

	if !cfg.AllowHTTP {
		t.Error("AllowHTTP = false, want true")
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}

	if cfg.Callback.Port != 4444 {
		t.Errorf("Callback.Port = %d", cfg.Callback.Port)
	}

	if cfg.Client.ClientID != "proxy" {
		t.Errorf("Client.ClientID = %q", cfg.Client.ClientID)
	}
}

func TestLoad_RejectsMissingMCPURL(t *testing.T) {
	path := writeTOML(t, `allow_http = true`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want missing mcp_url")
	}
}

func TestLoad_RejectsNonLoopbackHTTPWithoutAllow(t *testing.T) {
	path := writeTOML(t, `mcp_url = "http://example.com/mcp"`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want http without allow_http")
	}
}

func TestLoad_AllowsLoopbackHTTPWithoutAllow(t *testing.T) {
	path := writeTOML(t, `mcp_url = "http://localhost:8181/mcp"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.AllowHTTP {
		t.Error("AllowHTTP = true, want default false")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil {
		t.Fatal("Load() error = nil, want missing file")
	}
}

func TestLoad_ConfidentialClientRequiresAuthMethod(t *testing.T) {
	path := writeTOML(t, `
mcp_url = "https://mcp.example.example/mcp"

[client]
client_id = "proxy"
client_secret = "s3cret"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want token_endpoint_auth_method")
	}
}

func TestLoad_RejectsCallbackPathWithoutSlash(t *testing.T) {
	path := writeTOML(t, `
mcp_url = "https://mcp.example.example/mcp"

[callback]
path = "oauth/callback"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want callback.path")
	}
}

func writeTOML(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "privx-mcp-proxy.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}
