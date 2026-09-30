package config

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseServiceSecrets(t *testing.T) {
	a := strings.Repeat("a", 32)
	b := strings.Repeat("b", 32)
	got, err := ParseServiceSecrets("svc-ci " + a + "| svc-ci " + b)
	if err != nil {
		t.Fatalf("ParseServiceSecrets: %v", err)
	}
	if len(got) != 2 || got[0].Username != "svc-ci" || got[1].Username != "svc-ci" {
		t.Fatalf("usernames = %#v", got)
	}
	if got[0].Sum != sha256.Sum256([]byte(a)) || got[1].Sum != sha256.Sum256([]byte(b)) {
		t.Fatal("sums do not match the secrets")
	}

	if _, err := ParseServiceSecrets("svc-ci " + a + "|svc-nightly " + a); err == nil || !strings.Contains(err.Error(), "repeated secret") {
		t.Fatalf("duplicate secret: %v", err)
	}
	if _, err := ParseServiceSecrets("svc-ci " + a[:31]); err == nil || !strings.Contains(err.Error(), "shorter than 32") {
		t.Fatalf("short secret: %v", err)
	}
	if _, err := ParseServiceSecrets("svc-ci " + a + " tail"); err == nil || !strings.Contains(err.Error(), "space") {
		t.Fatalf("embedded space: %v", err)
	}
	if _, err := ParseServiceSecrets("svc-ci " + a + "|"); err == nil || !strings.Contains(err.Error(), "empty mapping") {
		t.Fatalf("trailing pipe: %v", err)
	}
	if _, err := ParseServiceSecrets("svc-ci" + a); err == nil || !strings.Contains(err.Error(), "no space") {
		t.Fatalf("no space: %v", err)
	}
}

func TestLoadConfig_M2MServiceSecrets(t *testing.T) {
	keyFile := writeKeyFile(t)
	secret := strings.Repeat("c", 64)

	t.Run("https loopback", func(t *testing.T) {
		cfg := loadM2M(t, keyFile, "https://127.0.0.1:8181", "svc-ci "+secret, "")
		if cfg.Server.AuthMode != "m2m" || len(cfg.Server.ServiceSecrets) != 1 || cfg.Server.ServiceSecrets[0].Username != "svc-ci" {
			t.Fatalf("mapping = %#v mode %q", cfg.Server.ServiceSecrets, cfg.Server.AuthMode)
		}
		if cfg.Server.serviceSecretsRaw != "" {
			t.Fatal("plaintext service_secrets retained")
		}
		if cfg.OAuth.IdentityClaimField != "email" {
			t.Fatalf("identity default = %q", cfg.OAuth.IdentityClaimField)
		}
	})

	for _, raw := range []string{
		"https://mcp.example.com",
		"http://mcp.example.com",
		"http://localhost:8181",
		"http://127.0.0.1:8181",
		"http://[::1]:8181",
	} {
		t.Run(raw, func(t *testing.T) {
			loadM2M(t, keyFile, raw, "svc-ci "+secret, "")
			if PublicURLIsHTTPS(raw) != strings.HasPrefix(raw, "https://") {
				t.Fatalf("PublicURLIsHTTPS(%q)", raw)
			}
		})
	}

	for _, raw := range []string{
		"not-a-url",
		"https://",
		"ftp://mcp.example.com",
	} {
		t.Run(raw, func(t *testing.T) {
			err := loadM2MErr(t, keyFile, raw, "svc-ci "+secret, "")
			if err == nil || !strings.Contains(err.Error(), "public_url") {
				t.Fatalf("public_url: %v", err)
			}
		})
	}

	t.Run("empty secrets", func(t *testing.T) {
		err := loadM2MErr(t, keyFile, "https://mcp.example.com", "", "")
		if err == nil || !strings.Contains(err.Error(), "service_secrets is required") {
			t.Fatalf("empty secrets: %v", err)
		}
	})

	t.Run("bad auth mode", func(t *testing.T) {
		content := strings.Replace(m2mTOML(keyFile, "https://mcp.example.com", "svc-ci "+secret, ""), `auth_mode = "m2m"`, `auth_mode = "both"`, 1)
		err := loadTOML(t, content)
		if err == nil || !strings.Contains(err.Error(), "auth_mode") {
			t.Fatalf("auth mode: %v", err)
		}
	})

	for _, tc := range []struct{ name, block, want string }{
		{"issuer", "issuer_url = \"https://idp.example.com\"\n", "oauth.issuer_url"},
		{"audience", "audience = \"test-client\"\n", "oauth.audience"},
		{"jwks", "jwks_uri = \"https://idp.example.com/jwks\"\n", "oauth.jwks_uri"},
		{"scopes", "scopes = [\"openid\"]\n", "oauth.scopes"},
		{"dcr id", "dcr_stub_client_id = \"id\"\n", "oauth.dcr_stub_client_id"},
		{"dcr secret", "dcr_stub_client_secret = \"secret\"\n", "oauth.dcr_stub_client_secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadM2MErr(t, keyFile, "https://mcp.example.com", "svc-ci "+secret, "[oauth]\n"+tc.block)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: %v", tc.name, err)
			}
		})
	}

	t.Run("oauth rejects secrets", func(t *testing.T) {
		content := `
[server]
public_url = "http://localhost:8181"
auth_mode = "oauth"
service_secrets = "svc-ci ` + secret + `"

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
		err := loadTOML(t, content)
		if err == nil || !strings.Contains(err.Error(), "service_secrets must be empty") {
			t.Fatalf("oauth secrets: %v", err)
		}
	})
}

func TestLoadConfig_ServiceSecretsEnvReplacesFile(t *testing.T) {
	keyFile := writeKeyFile(t)
	envSecret := strings.Repeat("d", 32)
	t.Setenv("SERVER_SERVICE_SECRETS", "svc-nightly "+envSecret)
	cfg := loadM2M(t, keyFile, "https://127.0.0.1:8181", "svc-ci "+strings.Repeat("e", 32), "")
	if len(cfg.Server.ServiceSecrets) != 1 || cfg.Server.ServiceSecrets[0].Username != "svc-nightly" {
		t.Fatalf("env mapping = %#v", cfg.Server.ServiceSecrets)
	}
	if cfg.Server.ServiceSecrets[0].Sum != sha256.Sum256([]byte(envSecret)) {
		t.Fatal("env secret was not the one hashed")
	}
	if cfg.Server.serviceSecretsRaw != "" {
		t.Fatal("plaintext service_secrets retained")
	}
}

func TestLoadConfig_AuthModeEnvReplacesFile(t *testing.T) {
	keyFile := writeKeyFile(t)
	t.Setenv("SERVER_AUTH_MODE", "oauth")
	err := loadM2MErr(t, keyFile, "https://mcp.example.com", "svc-ci "+strings.Repeat("f", 32), "")
	if err == nil || !strings.Contains(err.Error(), "oauth.issuer_url") {
		t.Fatalf("auth mode env: %v", err)
	}
}

func loadM2M(t *testing.T, keyFile, publicURL, secrets, oauth string) *Config {
	t.Helper()
	path := writeTOML(t, m2mTOML(keyFile, publicURL, secrets, oauth))
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg
}

func loadM2MErr(t *testing.T, keyFile, publicURL, secrets, oauth string) error {
	t.Helper()
	path := writeTOML(t, m2mTOML(keyFile, publicURL, secrets, oauth))
	_, err := LoadConfig(path)
	return err
}

func loadTOML(t *testing.T, content string) error {
	t.Helper()
	path := writeTOML(t, content)
	_, err := LoadConfig(path)
	return err
}

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func m2mTOML(keyFile, publicURL, secrets, oauth string) string {
	return `
[server]
public_url = "` + publicURL + `"
auth_mode = "m2m"
service_secrets = "` + secrets + `"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
` + oauth
}
