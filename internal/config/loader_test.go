package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKeyFile creates a dummy RSA key file in a temp dir and returns its
// path. Config-loading tests that expect success must reference a real file
// because resolvePrivXSigningKeyFile now verifies the key file exists.
func writeKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}
	return path
}

// writeTLSFiles creates dummy TLS cert and key files in a temp dir and returns
// their paths. TLS validation now verifies both files exist, so tests that
// configure TLS must reference real files.
func writeTLSFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(t.TempDir(), "tls-cert.pem")
	keyPath = filepath.Join(t.TempDir(), "tls-key.pem")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() cert failed: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("dummy key"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() key failed: %v", err)
	}
	return certPath, keyPath
}

func TestLoadConfig_FromTOMLFile(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
name = "test-server"
version = "2.0.0"
public_url = "http://localhost:8181"
disable_localhost_protection = true
stateless = true
log_file = "/tmp/privx-mcp.log"
log_level = "debug"

[privx_auth]
privx_base_url = "https://privx.example.com"
audience = "api://test-privx"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"
token_issuer = "test-issuer"
subject_format = "dn"
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "oauth-secret"
api_client_id = "api-client-id"
api_client_secret = "api-client-secret"
ca_cert = "/tmp/ca.pem"

[permissions]
default_read_only = false
whitelist = ["host-", "user-", "test-"]
blacklist = ["host-delete", "user-delete-"]
source_type = "AD"
session_cache_ttl = "45s"
request_window_seconds = 60
max_requests_per_window = 100
maxed_window_wait_seconds = 30

[oauth]
issuer_url = "https://idp.example.com"
audience = "api://test-idp"
jwks_cache_ttl = "30m"
identity_claim_field = "preferred_username"
identity_mapping_rule = "strip-domain"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Server.Name != "test-server" {
		t.Errorf("Server.Name = %q, want %q", cfg.Server.Name, "test-server")
	}
	if cfg.Server.Version != "2.0.0" {
		t.Errorf("Server.Version = %q, want %q", cfg.Server.Version, "2.0.0")
	}
	if cfg.Server.LogFile != "/tmp/privx-mcp.log" {
		t.Errorf("Server.LogFile = %q, want %q", cfg.Server.LogFile, "/tmp/privx-mcp.log")
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("Server.LogLevel = %q, want %q", cfg.Server.LogLevel, "debug")
	}
	if !cfg.Server.DisableLocalhostProtection {
		t.Errorf("Server.DisableLocalhostProtection = %v, want true", cfg.Server.DisableLocalhostProtection)
	}
	if !cfg.Server.Stateless {
		t.Errorf("Server.Stateless = %v, want true", cfg.Server.Stateless)
	}
	if cfg.PrivXAuth.PrivXBaseURL != "https://privx.example.com" {
		t.Errorf("PrivXAuth.PrivXBaseURL = %q, want %q", cfg.PrivXAuth.PrivXBaseURL, "https://privx.example.com")
	}
	if cfg.PrivXAuth.PrivXJWTAudience != "api://test-privx" {
		t.Errorf("PrivXAuth.PrivXJWTAudience = %q, want %q", cfg.PrivXAuth.PrivXJWTAudience, "api://test-privx")
	}
	if cfg.OAuth.ExpectedAudience != "api://test-idp" {
		t.Errorf("OAuth.ExpectedAudience = %q, want %q", cfg.OAuth.ExpectedAudience, "api://test-idp")
	}
	if cfg.PrivXAuth.RSAKeyFile != keyFile {
		t.Errorf("PrivXAuth.RSAKeyFile = %q, want %q", cfg.PrivXAuth.RSAKeyFile, keyFile)
	}
	if cfg.PrivXAuth.RSAKeyID != "key-1" {
		t.Errorf("PrivXAuth.RSAKeyID = %q, want %q", cfg.PrivXAuth.RSAKeyID, "key-1")
	}
	if cfg.PrivXAuth.TokenIssuer != "test-issuer" {
		t.Errorf("PrivXAuth.TokenIssuer = %q, want %q", cfg.PrivXAuth.TokenIssuer, "test-issuer")
	}
	if cfg.PrivXAuth.SubjectFormat != "dn" {
		t.Errorf("PrivXAuth.SubjectFormat = %q, want %q", cfg.PrivXAuth.SubjectFormat, "dn")
	}
	if cfg.PrivXAuth.APIOAuthClientID != "privx-external" {
		t.Errorf("PrivXAuth.APIOAuthClientID = %q, want %q", cfg.PrivXAuth.APIOAuthClientID, "privx-external")
	}
	if cfg.PrivXAuth.APIOAuthClientSecret != "oauth-secret" {
		t.Errorf("PrivXAuth.APIOAuthClientSecret = %q, want %q", cfg.PrivXAuth.APIOAuthClientSecret, "oauth-secret")
	}
	if cfg.PrivXAuth.APIClientID != "api-client-id" {
		t.Errorf("PrivXAuth.APIClientID = %q, want %q", cfg.PrivXAuth.APIClientID, "api-client-id")
	}
	if cfg.PrivXAuth.APIClientSecret != "api-client-secret" {
		t.Errorf("PrivXAuth.APIClientSecret = %q, want %q", cfg.PrivXAuth.APIClientSecret, "api-client-secret")
	}
	if cfg.PrivXAuth.CACert != "/tmp/ca.pem" {
		t.Errorf("PrivXAuth.CACert = %q, want %q", cfg.PrivXAuth.CACert, "/tmp/ca.pem")
	}
	if cfg.OAuth.JWKSCacheTTL != 30*time.Minute {
		t.Errorf("OAuth.JWKSCacheTTL = %v, want %v", cfg.OAuth.JWKSCacheTTL, 30*time.Minute)
	}
	if cfg.OAuth.IdentityClaimField != "preferred_username" {
		t.Errorf("OAuth.IdentityClaimField = %q, want %q", cfg.OAuth.IdentityClaimField, "preferred_username")
	}
	if cfg.OAuth.IdentityMappingRule != "strip-domain" {
		t.Errorf("OAuth.IdentityMappingRule = %q, want %q", cfg.OAuth.IdentityMappingRule, "strip-domain")
	}
	if cfg.Permissions.DefaultReadOnly != false {
		t.Errorf("Permissions.DefaultReadOnly = %v, want false", cfg.Permissions.DefaultReadOnly)
	}
	if got := len(cfg.Permissions.Whitelist); got != 3 {
		t.Errorf("Permissions.Whitelist has %d entries, want 3", got)
	}
	if cfg.Permissions.Whitelist[0] != "host-" || cfg.Permissions.Whitelist[1] != "user-" || cfg.Permissions.Whitelist[2] != "test-" {
		t.Errorf("Permissions.Whitelist = %v, want [host- user- test-]", cfg.Permissions.Whitelist)
	}
	if got := len(cfg.Permissions.Blacklist); got != 2 {
		t.Errorf("Permissions.Blacklist has %d entries, want 2", got)
	}
	if cfg.Permissions.Blacklist[0] != "host-delete" || cfg.Permissions.Blacklist[1] != "user-delete-" {
		t.Errorf("Permissions.Blacklist = %v, want [host-delete user-delete-]", cfg.Permissions.Blacklist)
	}
	if cfg.Permissions.SessionCacheTTL != 45*time.Second {
		t.Errorf("Permissions.SessionCacheTTL = %v, want %v", cfg.Permissions.SessionCacheTTL, 45*time.Second)
	}
	if cfg.Permissions.RefreshCooldown != time.Minute {
		t.Errorf("Permissions.RefreshCooldown default = %v, want %v", cfg.Permissions.RefreshCooldown, time.Minute)
	}
	if cfg.Permissions.RequestWindowSeconds != 60 {
		t.Errorf("Permissions.RequestWindowSeconds = %d, want 60", cfg.Permissions.RequestWindowSeconds)
	}
	if cfg.Permissions.MaxRequestsPerWindow != 100 {
		t.Errorf("Permissions.MaxRequestsPerWindow = %d, want 100", cfg.Permissions.MaxRequestsPerWindow)
	}
	if cfg.Permissions.MaxedWindowWaitSeconds != 30 {
		t.Errorf("Permissions.MaxedWindowWaitSeconds = %d, want 30", cfg.Permissions.MaxedWindowWaitSeconds)
	}
	if cfg.Permissions.SourceType != "AD" {
		t.Errorf("Permissions.SourceType = %q, want %q", cfg.Permissions.SourceType, "AD")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Minimal TOML with only required fields
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Server.Name != "privx-mcp-server" {
		t.Errorf("Server.Name default = %q, want %q", cfg.Server.Name, "privx-mcp-server")
	}
	if cfg.Server.AuthMode != "oauth" {
		t.Errorf("Server.AuthMode default = %q, want %q", cfg.Server.AuthMode, "oauth")
	}
	if cfg.PrivXAuth.TokenIssuer != "privx-mcp" {
		t.Errorf("PrivXAuth.TokenIssuer default = %q, want %q", cfg.PrivXAuth.TokenIssuer, "privx-mcp")
	}
	if cfg.PrivXAuth.SubjectFormat != "plain" {
		t.Errorf("PrivXAuth.SubjectFormat default = %q, want %q", cfg.PrivXAuth.SubjectFormat, "plain")
	}
	if cfg.OAuth.JWKSCacheTTL != time.Hour {
		t.Errorf("OAuth.JWKSCacheTTL default = %v, want %v", cfg.OAuth.JWKSCacheTTL, time.Hour)
	}
	if cfg.OAuth.IdentityClaimField != "email" {
		t.Errorf("OAuth.IdentityClaimField default = %q, want %q", cfg.OAuth.IdentityClaimField, "email")
	}
	if cfg.OAuth.IdentityMappingRule != "as-is" {
		t.Errorf("OAuth.IdentityMappingRule default = %q, want %q", cfg.OAuth.IdentityMappingRule, "as-is")
	}
	if cfg.Permissions.DefaultReadOnly != true {
		t.Errorf("Permissions.DefaultReadOnly default = %v, want true", cfg.Permissions.DefaultReadOnly)
	}
	if cfg.Permissions.SessionCacheTTL != 30*time.Second {
		t.Errorf("Permissions.SessionCacheTTL default = %v, want %v", cfg.Permissions.SessionCacheTTL, 30*time.Second)
	}
	if cfg.Permissions.RefreshCooldown != time.Minute {
		t.Errorf("Permissions.RefreshCooldown default = %v, want %v", cfg.Permissions.RefreshCooldown, time.Minute)
	}
	if cfg.Permissions.RequestWindowSeconds != 0 {
		t.Errorf("Permissions.RequestWindowSeconds default = %d, want 0", cfg.Permissions.RequestWindowSeconds)
	}
	if cfg.Permissions.MaxRequestsPerWindow != 0 {
		t.Errorf("Permissions.MaxRequestsPerWindow default = %d, want 0", cfg.Permissions.MaxRequestsPerWindow)
	}
	if cfg.Permissions.MaxedWindowWaitSeconds != 0 {
		t.Errorf("Permissions.MaxedWindowWaitSeconds default = %d, want 0", cfg.Permissions.MaxedWindowWaitSeconds)
	}
	if cfg.Permissions.EnableSensitiveDataTools {
		t.Errorf("Permissions.EnableSensitiveDataTools default = %v, want false", cfg.Permissions.EnableSensitiveDataTools)
	}
	if cfg.Permissions.SensitiveDataToolsAllowNonAdmin {
		t.Errorf("Permissions.SensitiveDataToolsAllowNonAdmin default = %v, want false", cfg.Permissions.SensitiveDataToolsAllowNonAdmin)
	}
	if cfg.Server.LogFile != "" {
		t.Errorf("Server.LogFile default = %q, want empty string", cfg.Server.LogFile)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("Server.LogLevel default = %q, want %q", cfg.Server.LogLevel, "info")
	}
	if cfg.Server.DisableLocalhostProtection {
		t.Errorf("Server.DisableLocalhostProtection default = %v, want false", cfg.Server.DisableLocalhostProtection)
	}
	if !cfg.Server.Stateless {
		t.Errorf("Server.Stateless default = %v, want true", cfg.Server.Stateless)
	}
}

func TestLoadConfig_SensitiveDataToolsFromTOML(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
enable_sensitive_data_tools = true
sensitive_data_tools_allow_non_admin = true

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !cfg.Permissions.EnableSensitiveDataTools {
		t.Error("Permissions.EnableSensitiveDataTools = false, want true")
	}
	if !cfg.Permissions.SensitiveDataToolsAllowNonAdmin {
		t.Error("Permissions.SensitiveDataToolsAllowNonAdmin = false, want true")
	}
}

func TestLoadConfig_SensitiveDataToolsEnvOverride(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PERMISSIONS_ENABLE_SENSITIVE_DATA_TOOLS", "true")
	t.Setenv("PERMISSIONS_SENSITIVE_DATA_TOOLS_ALLOW_NON_ADMIN", "1")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if !cfg.Permissions.EnableSensitiveDataTools {
		t.Error("env PERMISSIONS_ENABLE_SENSITIVE_DATA_TOOLS=true did not enable the flag")
	}
	if !cfg.Permissions.SensitiveDataToolsAllowNonAdmin {
		t.Error("env PERMISSIONS_SENSITIVE_DATA_TOOLS_ALLOW_NON_ADMIN=1 did not enable the flag")
	}
}

func TestLoadConfig_SessionCacheTTLZeroDisablesCache(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
session_cache_ttl = "0"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Permissions.SessionCacheTTL != 0 {
		t.Fatalf("Permissions.SessionCacheTTL = %v, want 0", cfg.Permissions.SessionCacheTTL)
	}
}

func TestLoadConfig_RefreshCooldownZeroDisablesRefresh(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
refresh_cooldown = "0"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Permissions.RefreshCooldown != 0 {
		t.Fatalf("Permissions.RefreshCooldown = %v, want 0", cfg.Permissions.RefreshCooldown)
	}
}

func TestLoadConfig_RefreshCooldownFromTOML(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
refresh_cooldown = "90s"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Permissions.RefreshCooldown != 90*time.Second {
		t.Fatalf("Permissions.RefreshCooldown = %v, want 90s", cfg.Permissions.RefreshCooldown)
	}
}

func TestLoadConfig_RefreshCooldownNegativeRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
refresh_cooldown = "-1s"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error for negative permissions.refresh_cooldown")
	}
	if !strings.Contains(err.Error(), "permissions.refresh_cooldown") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_SessionCacheTTLNegativeRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
session_cache_ttl = "-1s"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error for negative permissions.session_cache_ttl")
	}
	if !strings.Contains(err.Error(), "permissions.session_cache_ttl") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_RateLimitOneSidedRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
request_window_seconds = 60
max_requests_per_window = 0

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error for one-sided rate limit config")
	}
	if !strings.Contains(err.Error(), "request_window_seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_RateLimitNegativeRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
request_window_seconds = -1
max_requests_per_window = 10

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error for negative request_window_seconds")
	}
	if !strings.Contains(err.Error(), "request_window_seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_MaxedWindowWaitWithoutRateLimitRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
maxed_window_wait_seconds = 15

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error for maxed_window_wait_seconds without rate limit")
	}
	if !strings.Contains(err.Error(), "maxed_window_wait_seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_MaxedWindowWaitNegativeRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
request_window_seconds = 15
max_requests_per_window = 5
maxed_window_wait_seconds = -1

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error for negative maxed_window_wait_seconds")
	}
	if !strings.Contains(err.Error(), "maxed_window_wait_seconds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_EnvVarOverride(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://from-file.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "file-key-id"
token_issuer = "file-issuer"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PRIVX_PRIVX_BASE_URL", "https://from-env.example.com")
	t.Setenv("PRIVX_TOKEN_ISSUER", "env-issuer")
	t.Setenv("PRIVX_API_CLIENT_ID", "env-api-client")
	t.Setenv("PRIVX_CA_CERT", "/tmp/env-ca.pem")
	t.Setenv("SERVER_NAME", "env-server")
	t.Setenv("SERVER_LOG_FILE", "/var/log/from-env.log")
	t.Setenv("SERVER_LOG_LEVEL", "error")
	t.Setenv("SERVER_DISABLE_LOCALHOST_PROTECTION", "1")
	t.Setenv("SERVER_STATELESS", "true")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.PrivXAuth.PrivXBaseURL != "https://from-env.example.com" {
		t.Errorf("PrivXAuth.PrivXBaseURL = %q, want env value %q", cfg.PrivXAuth.PrivXBaseURL, "https://from-env.example.com")
	}
	if cfg.PrivXAuth.TokenIssuer != "env-issuer" {
		t.Errorf("PrivXAuth.TokenIssuer = %q, want env value %q", cfg.PrivXAuth.TokenIssuer, "env-issuer")
	}
	if cfg.Server.Name != "env-server" {
		t.Errorf("Server.Name = %q, want env value %q", cfg.Server.Name, "env-server")
	}
	if cfg.Server.LogFile != "/var/log/from-env.log" {
		t.Errorf("Server.LogFile = %q, want env value %q", cfg.Server.LogFile, "/var/log/from-env.log")
	}
	if cfg.Server.LogLevel != "error" {
		t.Errorf("Server.LogLevel = %q, want env value %q", cfg.Server.LogLevel, "error")
	}
	if !cfg.Server.DisableLocalhostProtection {
		t.Errorf("Server.DisableLocalhostProtection = %v, want env value true", cfg.Server.DisableLocalhostProtection)
	}
	if !cfg.Server.Stateless {
		t.Errorf("Server.Stateless = %v, want env value true", cfg.Server.Stateless)
	}
	if cfg.PrivXAuth.APIClientID != "env-api-client" {
		t.Errorf("PrivXAuth.APIClientID = %q, want env value %q", cfg.PrivXAuth.APIClientID, "env-api-client")
	}
	if cfg.PrivXAuth.CACert != "/tmp/env-ca.pem" {
		t.Errorf("PrivXAuth.CACert = %q, want env value %q", cfg.PrivXAuth.CACert, "/tmp/env-ca.pem")
	}
	// File value should be preserved when no env var overrides it
	if cfg.PrivXAuth.RSAKeyFile != keyFile {
		t.Errorf("PrivXAuth.RSAKeyFile = %q, want file value %q", cfg.PrivXAuth.RSAKeyFile, keyFile)
	}
}

func TestLoadConfig_EnvVarConfigPath(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PRIVX_MCP_CONFIG", path)

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.PrivXAuth.PrivXBaseURL != "https://privx.example.com" {
		t.Errorf("PrivXAuth.PrivXBaseURL = %q, want %q", cfg.PrivXAuth.PrivXBaseURL, "https://privx.example.com")
	}
}

func TestLoadConfig_ValidationError_MissingRequired(t *testing.T) {
	tests := []struct {
		name    string
		content string
		missing []string
	}{
		{
			name:    "all required missing",
			content: ``,
			missing: []string{"privx_auth.privx_base_url", "privx_auth.rsa_key_file", "privx_auth.rsa_key_id", "permissions.source_type"},
		},
		{
			name: "missing rsa_key_file and rsa_key_id",
			content: `
[privx_auth]
privx_base_url = "https://privx.example.com"
`,
			missing: []string{"privx_auth.rsa_key_file", "privx_auth.rsa_key_id", "permissions.source_type"},
		},
		{
			name: "missing only rsa_key_id",
			content: `
[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
`,
			missing: []string{"privx_auth.rsa_key_id", "permissions.source_type"},
		},
		{
			name: "missing only source_type",
			content: `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`,
			missing: []string{"permissions.source_type"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := LoadConfig(path)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}

			for _, field := range tt.missing {
				if !strings.Contains(err.Error(), field) {
					t.Errorf("error %q does not mention missing field %q", err.Error(), field)
				}
			}
		})
	}
}

func TestLoadConfig_OAuthIssuerLegacyAliasRejected(t *testing.T) {
	content := `
[server]
public_url = "http://localhost:8181"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/tmp/key.pem"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error when using legacy oauth.issuer")
	}
	if !strings.Contains(err.Error(), "oauth.issuer_url") {
		t.Fatalf("expected error to mention oauth.issuer_url, got: %v", err)
	}
}

func TestLoadConfig_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(path, []byte("not valid [[ toml"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("error %q does not mention config file read failure", err.Error())
	}
}

func TestLoadConfig_MissingFile_Skipped(t *testing.T) {
	keyFile := writeKeyFile(t)
	t.Setenv("PRIVX_MCP_CONFIG", "")
	t.Setenv("SERVER_PUBLIC_URL", "http://localhost:8181")
	t.Setenv("PRIVX_PRIVX_BASE_URL", "https://privx.example.com")
	t.Setenv("PRIVX_RSA_KEY_FILE", keyFile)
	t.Setenv("PRIVX_RSA_KEY_ID", "key-1")
	t.Setenv("PERMISSIONS_SOURCE_TYPE", "AD")
	t.Setenv("OAUTH_ISSUER_URL", "https://idp.example.com")
	t.Setenv("OAUTH_AUDIENCE", "test-client")

	cfg, err := LoadConfig("/nonexistent/path/config.toml")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.PrivXAuth.PrivXBaseURL != "https://privx.example.com" {
		t.Errorf("PrivXAuth.PrivXBaseURL = %q, want %q", cfg.PrivXAuth.PrivXBaseURL, "https://privx.example.com")
	}
	if cfg.Permissions.SourceType != "AD" {
		t.Errorf("Permissions.SourceType = %q, want %q", cfg.Permissions.SourceType, "AD")
	}
}

func TestLoadConfig_MissingFile_ValidationStillApplies(t *testing.T) {
	t.Setenv("PRIVX_MCP_CONFIG", "")
	t.Setenv("SERVER_PUBLIC_URL", "")
	t.Setenv("PRIVX_PRIVX_BASE_URL", "")
	t.Setenv("PRIVX_RSA_KEY_FILE", "")
	t.Setenv("PRIVX_RSA_KEY_ID", "")
	t.Setenv("PERMISSIONS_SOURCE_TYPE", "")
	t.Setenv("OAUTH_ISSUER_URL", "")
	t.Setenv("OAUTH_AUDIENCE", "")

	_, err := LoadConfig("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected validation error when file is missing and required env vars are unset")
	}
	if !strings.Contains(err.Error(), "missing required configuration fields") {
		t.Fatalf("expected validation error, got: %v", err)
	}
}

func TestLoadConfig_NoFileNoEnvVar(t *testing.T) {
	// When no file path and no PRIVX_MCP_CONFIG, provide required via env vars
	keyFile := writeKeyFile(t)
	t.Setenv("SERVER_PUBLIC_URL", "http://localhost:8181")
	t.Setenv("PRIVX_PRIVX_BASE_URL", "https://privx.example.com")
	t.Setenv("PRIVX_RSA_KEY_FILE", keyFile)
	t.Setenv("PRIVX_RSA_KEY_ID", "key-1")
	t.Setenv("PERMISSIONS_SOURCE_TYPE", "AD")
	t.Setenv("OAUTH_ISSUER_URL", "https://idp.example.com")
	t.Setenv("OAUTH_AUDIENCE", "test-client")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.PrivXAuth.PrivXBaseURL != "https://privx.example.com" {
		t.Errorf("PrivXAuth.PrivXBaseURL = %q, want %q", cfg.PrivXAuth.PrivXBaseURL, "https://privx.example.com")
	}
	if cfg.Permissions.SourceType != "AD" {
		t.Errorf("Permissions.SourceType = %q, want %q", cfg.Permissions.SourceType, "AD")
	}
}

func TestLoadConfig_InvalidLogLevel(t *testing.T) {
	keyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"
log_level = "trace"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid log_level")
	}
	if !strings.Contains(err.Error(), "server.log_level") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_TLSVarsRequireHTTPSPublicURL(t *testing.T) {
	certPath, keyPath := writeTLSFiles(t)
	missingCert := filepath.Join(t.TempDir(), "missing-cert.pem")
	missingKey := filepath.Join(t.TempDir(), "missing-key.pem")

	tests := []struct {
		name      string
		publicURL string
		tlsCert   string
		tlsKey    string
		wantErr   string // non-empty substring expected in error; empty means no error
	}{
		{
			name:      "tls set with http url rejected",
			publicURL: "http://localhost:8181",
			tlsCert:   certPath,
			tlsKey:    keyPath,
			wantErr:   "server.public_url must use https://",
		},
		{
			name:      "tls set with https url accepted",
			publicURL: "https://mcp.example.com:8181",
			tlsCert:   certPath,
			tlsKey:    keyPath,
			wantErr:   "",
		},
		{
			name:      "https url without tls accepted (reverse proxy)",
			publicURL: "https://mcp.example.com",
			tlsCert:   "",
			tlsKey:    "",
			wantErr:   "",
		},
		{
			name:      "http url without tls accepted (local dev)",
			publicURL: "http://localhost:8181",
			tlsCert:   "",
			tlsKey:    "",
			wantErr:   "",
		},
		{
			name:      "only cert set rejected",
			publicURL: "http://localhost:8181",
			tlsCert:   certPath,
			tlsKey:    "",
			wantErr:   "must be set together",
		},
		{
			name:      "only key set rejected",
			publicURL: "http://localhost:8181",
			tlsCert:   "",
			tlsKey:    keyPath,
			wantErr:   "must be set together",
		},
		{
			name:      "tls set with missing cert file rejected",
			publicURL: "https://mcp.example.com:8181",
			tlsCert:   missingCert,
			tlsKey:    keyPath,
			wantErr:   "server.tls_cert_file not found",
		},
		{
			name:      "tls set with missing key file rejected",
			publicURL: "https://mcp.example.com:8181",
			tlsCert:   certPath,
			tlsKey:    missingKey,
			wantErr:   "server.tls_key_file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyFile := writeKeyFile(t)
			content := `
[server]
public_url = "` + tt.publicURL + `"
tls_cert_file = "` + tt.tlsCert + `"
tls_key_file = "` + tt.tlsKey + `"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := LoadConfig(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected validation error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestLoadConfig_TLSVarsRequireHTTPSPublicURL_DevMode(t *testing.T) {
	certPath, keyPath := writeTLSFiles(t)
	rsaKeyFile := writeKeyFile(t)
	content := `
[server]
public_url = "http://localhost:8181"
tls_cert_file = "` + certPath + `"
tls_key_file = "` + keyPath + `"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + rsaKeyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"

[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation error with tls set and http url")
	}
	if !strings.Contains(err.Error(), "server.public_url must use https://") {
		t.Fatalf("expected error about https public_url, got: %v", err)
	}
}

func TestParseDurationIfSet(t *testing.T) {
	t.Run("empty leaves target unchanged", func(t *testing.T) {
		d := 45 * time.Second
		parseDurationIfSet("", &d)
		if d != 45*time.Second {
			t.Fatalf("got %v", d)
		}
	})

	t.Run("valid duration", func(t *testing.T) {
		var d time.Duration
		parseDurationIfSet("30m", &d)
		if d != 30*time.Minute {
			t.Fatalf("got %v", d)
		}
	})

	t.Run("invalid duration leaves target unchanged", func(t *testing.T) {
		d := time.Hour
		parseDurationIfSet("not-a-duration", &d)
		if d != time.Hour {
			t.Fatalf("got %v", d)
		}
	})
}
