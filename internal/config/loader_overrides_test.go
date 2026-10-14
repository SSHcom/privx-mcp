package config

import (
	"testing"
	"time"
)

func TestApplyOAuthEnvOverrides(t *testing.T) {
	t.Setenv("SERVER_PUBLIC_URL", "https://mcp.example.com")
	t.Setenv("PRIVX_API_OAUTH_CLIENT_ID", "privx-external")
	t.Setenv("PRIVX_API_OAUTH_CLIENT_SECRET", "oauth-secret")
	t.Setenv("PRIVX_API_CLIENT_ID", "api-client")
	t.Setenv("PRIVX_API_CLIENT_SECRET", "api-secret")
	t.Setenv("PRIVX_CA_CERT", "/tmp/ca.pem")
	t.Setenv("OAUTH_ID_CLAIM_FIELD", "email")
	t.Setenv("OAUTH_ID_MAPPING_RULE", "as-is")
	t.Setenv("OAUTH_ISSUER_URL", "https://login.example.com")
	t.Setenv("OAUTH_SCOPES", "openid,profile,email")
	t.Setenv("OAUTH_AUDIENCE", "api://mcp-audience")
	t.Setenv("OAUTH_DCR_STUB_CLIENT_ID", "dcr-client-id")
	t.Setenv("OAUTH_DCR_STUB_CLIENT_SECRET", "dcr-client-secret")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Server.PublicURL != "https://mcp.example.com" {
		t.Fatalf("public_url mismatch: %q", cfg.Server.PublicURL)
	}
	if cfg.OAuth.IssuerURL != "https://login.example.com" {
		t.Fatalf("issuer mismatch: %q", cfg.OAuth.IssuerURL)
	}
	if cfg.OAuth.IdentityClaimField != "email" {
		t.Fatalf("claim_field mismatch: %q", cfg.OAuth.IdentityClaimField)
	}
	if cfg.OAuth.IdentityMappingRule != "as-is" {
		t.Fatalf("mapping_rule mismatch: %q", cfg.OAuth.IdentityMappingRule)
	}
	if cfg.PrivXAuth.APIOAuthClientID != "privx-external" {
		t.Fatalf("auth api oauth client_id mismatch: %q", cfg.PrivXAuth.APIOAuthClientID)
	}
	if cfg.PrivXAuth.APIOAuthClientSecret != "oauth-secret" {
		t.Fatalf("auth api oauth client_secret mismatch: %q", cfg.PrivXAuth.APIOAuthClientSecret)
	}
	if cfg.PrivXAuth.APIClientID != "api-client" {
		t.Fatalf("auth api client_id mismatch: %q", cfg.PrivXAuth.APIClientID)
	}
	if cfg.PrivXAuth.APIClientSecret != "api-secret" {
		t.Fatalf("auth api client_secret mismatch: %q", cfg.PrivXAuth.APIClientSecret)
	}
	if cfg.PrivXAuth.CACert != "/tmp/ca.pem" {
		t.Fatalf("auth ca_cert mismatch: %q", cfg.PrivXAuth.CACert)
	}
	if cfg.OAuth.ExpectedAudience != "api://mcp-audience" {
		t.Fatalf("audience mismatch: %q", cfg.OAuth.ExpectedAudience)
	}
	if len(cfg.OAuth.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(cfg.OAuth.Scopes))
	}
	if cfg.OAuth.DCRStubClientID != "dcr-client-id" {
		t.Fatalf("dcr client id mismatch: %q", cfg.OAuth.DCRStubClientID)
	}
	if cfg.OAuth.DCRStubClientSecret != "dcr-client-secret" {
		t.Fatalf("dcr client secret mismatch: %q", cfg.OAuth.DCRStubClientSecret)
	}
}

func TestValidateOAuth_RequiresProviderFields(t *testing.T) {
	base := PrivXAuthConfig{
		PrivXBaseURL: "https://privx.example.com",
		RSAKeyFile:   "/path/to/key",
		RSAKeyID:     "key-1",
	}

	cfg := &Config{
		PrivXAuth: base,
	}

	err := validate(cfg)
	if err == nil {
		t.Fatal("expected validation error when oauth provider fields are missing")
	}

	cfg.Server.PublicURL = "http://localhost:8181"
	cfg.Permissions.SourceType = "AD"
	cfg.OAuth = OAuthConfig{
		IssuerURL:          "https://login.example.com",
		ExpectedAudience:   "mcp-client",
		IdentityClaimField: "email",
	}
	if err := validate(cfg); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestApplyTLSAndRSAFileEnvOverrides(t *testing.T) {
	t.Setenv("SERVER_TLS_CERT_FILE", "/path/to/mcp-tls-cert.pem")
	t.Setenv("SERVER_TLS_KEY_FILE", "/path/to/mcp-tls-key.pem")
	t.Setenv("SERVER_DISABLE_LOCALHOST_PROTECTION", "true")
	t.Setenv("SERVER_STATELESS", "1")
	t.Setenv("PRIVX_RSA_KEY_FILE", "/path/to/private-key.pem")
	t.Setenv("PRIVX_RSA_PUBLIC_KEY_FILE", "/path/to/public-key.pem")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Server.TLSCertFile != "/path/to/mcp-tls-cert.pem" {
		t.Fatalf("tls_cert_file mismatch: %q", cfg.Server.TLSCertFile)
	}
	if cfg.Server.TLSKeyFile != "/path/to/mcp-tls-key.pem" {
		t.Fatalf("tls_key_file mismatch: %q", cfg.Server.TLSKeyFile)
	}
	if !cfg.Server.DisableLocalhostProtection {
		t.Fatalf("disable_localhost_protection mismatch: %v", cfg.Server.DisableLocalhostProtection)
	}
	if !cfg.Server.Stateless {
		t.Fatalf("stateless mismatch: %v", cfg.Server.Stateless)
	}
	if cfg.PrivXAuth.RSAKeyFile != "/path/to/private-key.pem" {
		t.Fatalf("rsa_key_file mismatch: %q", cfg.PrivXAuth.RSAKeyFile)
	}
	if cfg.PrivXAuth.RSAPublicKeyFile != "/path/to/public-key.pem" {
		t.Fatalf("rsa_public_key_file mismatch: %q", cfg.PrivXAuth.RSAPublicKeyFile)
	}
}

func TestApplyPermissionsSourceTypeEnvOverrides(t *testing.T) {
	t.Setenv("PERMISSIONS_SOURCE_TYPE", "MICROSOFTGRAPH")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Permissions.SourceType != "MICROSOFTGRAPH" {
		t.Fatalf("expected source_type override, got %q", cfg.Permissions.SourceType)
	}
}

func TestApplyPermissionsWhitelistEnvOverrides(t *testing.T) {
	t.Setenv("PERMISSIONS_WHITELIST", "host-, user-,test-")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if len(cfg.Permissions.Whitelist) != 3 {
		t.Fatalf("expected 3 prefixes, got %d", len(cfg.Permissions.Whitelist))
	}
	if cfg.Permissions.Whitelist[0] != "host-" || cfg.Permissions.Whitelist[1] != "user-" || cfg.Permissions.Whitelist[2] != "test-" {
		t.Fatalf("unexpected whitelist: %v", cfg.Permissions.Whitelist)
	}
}

func TestApplyPermissionsBlacklistEnvOverrides(t *testing.T) {
	t.Setenv("PERMISSIONS_BLACKLIST", "host-delete, user-delete-")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if len(cfg.Permissions.Blacklist) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(cfg.Permissions.Blacklist))
	}
	if cfg.Permissions.Blacklist[0] != "host-delete" || cfg.Permissions.Blacklist[1] != "user-delete-" {
		t.Fatalf("unexpected blacklist: %v", cfg.Permissions.Blacklist)
	}
}

func TestApplyPermissionsSessionCacheTTLEnvOverrides(t *testing.T) {
	t.Setenv("PERMISSIONS_SESSION_CACHE_TTL", "2m")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Permissions.SessionCacheTTL != 2*time.Minute {
		t.Fatalf("expected session cache ttl override, got %v", cfg.Permissions.SessionCacheTTL)
	}
}

func TestApplyPermissionsRefreshCooldownEnvOverrides(t *testing.T) {
	t.Setenv("PERMISSIONS_REFRESH_COOLDOWN", "45s")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Permissions.RefreshCooldown != 45*time.Second {
		t.Fatalf("expected refresh cooldown override, got %v", cfg.Permissions.RefreshCooldown)
	}
}

func TestApplyPermissionsRateLimitEnvOverrides(t *testing.T) {
	t.Setenv("PERMISSIONS_REQUEST_WINDOW_SECONDS", "90")
	t.Setenv("PERMISSIONS_MAX_REQUESTS_PER_WINDOW", "25")
	t.Setenv("PERMISSIONS_MAXED_WINDOW_WAIT_SECONDS", "12")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Permissions.RequestWindowSeconds != 90 {
		t.Fatalf("expected request window seconds override, got %d", cfg.Permissions.RequestWindowSeconds)
	}
	if cfg.Permissions.MaxRequestsPerWindow != 25 {
		t.Fatalf("expected max requests per window override, got %d", cfg.Permissions.MaxRequestsPerWindow)
	}
	if cfg.Permissions.MaxedWindowWaitSeconds != 12 {
		t.Fatalf("expected maxed window wait seconds override, got %d", cfg.Permissions.MaxedWindowWaitSeconds)
	}
}
