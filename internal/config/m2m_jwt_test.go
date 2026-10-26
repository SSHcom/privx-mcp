package config

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestParseM2MJWTIdentityMapper(t *testing.T) {
	got, err := ParseM2MJWTIdentityMapper("preferred_username jdone john.done| email ada@example.com ada")
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || got[0].Claim != "preferred_username" || got[0].Value != "jdone" || got[0].Username != "john.done" {
		t.Fatalf("rows = %#v", got)
	}

	if got[1].Claim != "email" || got[1].Username != "ada" {
		t.Fatalf("email row = %#v", got[1])
	}

	for _, tc := range []struct{ raw, want string }{
		{"sub jdone john.done", "preferred_username or email"},
		{"preferred_username jdone", "claim, value, and username"},
		{"preferred_username jdone john done", "claim, value, and username"},
		{"preferred_username jdone john.done|", "empty record"},
		{"email a@b ada|email a@b other", "repeated claim and value"},
	} {
		if _, err := ParseM2MJWTIdentityMapper(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: %v", tc.raw, err)
		}
	}
}

func TestLoadConfig_M2MJWT(t *testing.T) {
	keyFile := writeKeyFile(t)
	key := "0123456789abcdef"
	mapper := "preferred_username jdone john.done"

	cfg := loadM2MJWT(t, keyFile, "http://127.0.0.1:8181", key, mapper, "https://idp.example", "")
	if cfg.Server.AuthMode != "m2m-jwt" || !cfg.Server.M2MJWTKeySet {
		t.Fatalf("mode %q key set %v", cfg.Server.AuthMode, cfg.Server.M2MJWTKeySet)
	}

	if cfg.Server.M2MJWTKey != sha256.Sum256([]byte(key)) {
		t.Fatal("key hash mismatch")
	}

	if cfg.Server.m2mJWTKeyRaw != "" || cfg.Server.m2mJWTIdentityMapperRaw != "" {
		t.Fatal("plaintext jwt settings retained")
	}

	if cfg.Server.M2MJWTIssuer != "https://idp.example" || len(cfg.Server.M2MJWTIdentityMapper) != 1 {
		t.Fatalf("issuer %q mapper %#v", cfg.Server.M2MJWTIssuer, cfg.Server.M2MJWTIdentityMapper)
	}

	if err := loadM2MJWTErr(t, keyFile, "https://mcp.example.com", "short-key", mapper, "", ""); err == nil || !strings.Contains(err.Error(), "shorter than 12") {
		t.Fatalf("short key: %v", err)
	}

	if err := loadM2MJWTErr(t, keyFile, "https://mcp.example.com", "", mapper, "", ""); err == nil || !strings.Contains(err.Error(), "m2m_jwt_key is required") {
		t.Fatalf("empty key: %v", err)
	}

	if err := loadM2MJWTErr(t, keyFile, "https://mcp.example.com", key, "", "", ""); err == nil || !strings.Contains(err.Error(), "m2m_jwt_identity_mapper is required") {
		t.Fatalf("empty mapper: %v", err)
	}

	if err := loadM2MJWTErr(t, keyFile, "https://mcp.example.com", key, "sub jdone john.done", "", ""); err == nil || !strings.Contains(err.Error(), "preferred_username or email") {
		t.Fatalf("claim: %v", err)
	}

	identity := "m2m_identity_mapper = \"svc-ci " + strings.Repeat("a", 32) + "\"\n"
	if err := loadM2MJWTErr(t, keyFile, "https://mcp.example.com", key, mapper, "", identity); err == nil || !strings.Contains(err.Error(), "m2m_identity_mapper must be empty") {
		t.Fatalf("identity mapper: %v", err)
	}

	if err := loadM2MJWTErr(t, keyFile, "https://mcp.example.com", key, mapper, "", "[oauth]\nissuer_url = \"https://idp.example.com\"\n"); err == nil || !strings.Contains(err.Error(), "oauth.issuer_url") {
		t.Fatalf("oauth issuer: %v", err)
	}

	m2mBody := m2mTOML(keyFile, "https://mcp.example.com", "svc-ci "+strings.Repeat("a", 32), "")
	m2mBody = strings.Replace(m2mBody, `auth_mode = "m2m"`, "auth_mode = \"m2m\"\nm2m_jwt_key = \""+key+"\"", 1)
	if err := loadTOML(t, m2mBody); err == nil || !strings.Contains(err.Error(), "m2m_jwt_key must be empty") {
		t.Fatalf("m2m with jwt key: %v", err)
	}

	oauthBody := strings.Replace(m2mJWTTOML(keyFile, "http://localhost:8181", key, mapper, "", ""), `auth_mode = "m2m-jwt"`, `auth_mode = "oauth"`, 1)
	oauthBody += `
[oauth]
issuer_url = "https://idp.example.com"
audience = "test-client"
`
	if err := loadTOML(t, oauthBody); err == nil || !strings.Contains(err.Error(), "must be empty when server.auth_mode is oauth") {
		t.Fatalf("oauth with jwt key: %v", err)
	}
}

func TestLoadConfig_M2MJWTEnvReplacesFile(t *testing.T) {
	keyFile := writeKeyFile(t)
	envKey := "env-key-value!"
	t.Setenv("SERVER_M2M_JWT_KEY", envKey)
	t.Setenv("SERVER_M2M_JWT_IDENTITY_MAPPER", "email ada@example.com ada")
	t.Setenv("SERVER_M2M_JWT_ISSUER", "https://env.example")

	cfg := loadM2MJWT(t, keyFile, "https://127.0.0.1:8181", "file-key-value", "preferred_username jdone john.done", "https://file.example", "")
	if cfg.Server.M2MJWTKey != sha256.Sum256([]byte(envKey)) {
		t.Fatal("env key was not the one hashed")
	}

	if len(cfg.Server.M2MJWTIdentityMapper) != 1 || cfg.Server.M2MJWTIdentityMapper[0].Username != "ada" {
		t.Fatalf("env mapper = %#v", cfg.Server.M2MJWTIdentityMapper)
	}

	if cfg.Server.M2MJWTIssuer != "https://env.example" {
		t.Fatalf("issuer = %q", cfg.Server.M2MJWTIssuer)
	}
}

func loadM2MJWT(t *testing.T, keyFile, publicURL, key, mapper, issuer, extra string) *Config {
	t.Helper()

	path := writeTOML(t, m2mJWTTOML(keyFile, publicURL, key, mapper, issuer, extra))

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	return cfg
}

func loadM2MJWTErr(t *testing.T, keyFile, publicURL, key, mapper, issuer, extra string) error {
	t.Helper()

	path := writeTOML(t, m2mJWTTOML(keyFile, publicURL, key, mapper, issuer, extra))
	_, err := LoadConfig(path)

	return err
}

func m2mJWTTOML(keyFile, publicURL, key, mapper, issuer, extra string) string {
	return `
[server]
public_url = "` + publicURL + `"
auth_mode = "m2m-jwt"
m2m_jwt_key = "` + key + `"
m2m_jwt_identity_mapper = "` + mapper + `"
m2m_jwt_issuer = "` + issuer + `"
` + extra + `

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "` + keyFile + `"
rsa_key_id = "key-1"

[permissions]
source_type = "AD"
`
}
