package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// tomlConfig mirrors the TOML file structure with snake_case field names.
type tomlConfig struct {
	Server struct {
		Name       string `toml:"name"`
		Version    string `toml:"version"`
		PublicURL  string `toml:"public_url"`
		ListenAddr string `toml:"listen_addr"`
		TLSCert    string `toml:"tls_cert_file"`
		TLSKey     string `toml:"tls_key_file"`
		// DisableLocalhostProtection controls
		// mcp.StreamableHTTPOptions.DisableLocalhostProtection.
		DisableLocalhostProtection bool `toml:"disable_localhost_protection"`
		// Stateless controls mcp.StreamableHTTPOptions.Stateless.
		Stateless bool `toml:"stateless"`

		LogFile  string `toml:"log_file"`
		LogLevel string `toml:"log_level"`

		AuthMode       string `toml:"auth_mode"`
		ServiceSecrets string `toml:"service_secrets"`
	} `toml:"server"`

	PrivXAuth struct {
		PrivXBaseURL         string `toml:"privx_base_url"`
		Audience             string `toml:"audience"`
		RSAKeyFile           string `toml:"rsa_key_file"`
		RSAPublicKeyFile     string `toml:"rsa_public_key_file"`
		RSAKeyID             string `toml:"rsa_key_id"`
		TokenIssuer          string `toml:"token_issuer"`
		SubjectFormat        string `toml:"subject_format"`
		APIOAuthClientID     string `toml:"api_oauth_client_id"`
		APIOAuthClientSecret string `toml:"api_oauth_client_secret"`
		APIClientID          string `toml:"api_client_id"`
		APIClientSecret      string `toml:"api_client_secret"`
		CACert               string `toml:"ca_cert"`
	} `toml:"privx_auth"`

	Permissions struct {
		DefaultReadOnly        bool     `toml:"default_read_only"`
		Whitelist              []string `toml:"whitelist"`
		Blacklist              []string `toml:"blacklist"`
		SessionCacheTTL        string   `toml:"session_cache_ttl"`
		RefreshCooldown        string   `toml:"refresh_cooldown"`
		SourceType             string   `toml:"source_type"`
		RequestWindowSeconds   int      `toml:"request_window_seconds"`
		MaxRequestsPerWindow   int      `toml:"max_requests_per_window"`
		MaxedWindowWaitSeconds int      `toml:"maxed_window_wait_seconds"`
	} `toml:"permissions"`

	OAuth struct {
		IssuerURL    string   `toml:"issuer_url"`
		Scopes       []string `toml:"scopes"`
		JWKSURI      string   `toml:"jwks_uri"`
		Audience     string   `toml:"audience"`
		JWKSCacheTTL string   `toml:"jwks_cache_ttl"`

		IdentityClaimField  string `toml:"identity_claim_field"`
		IdentityMappingRule string `toml:"identity_mapping_rule"`

		DCRStubClientID     string `toml:"dcr_stub_client_id"`
		DCRStubClientSecret string `toml:"dcr_stub_client_secret"`
	} `toml:"oauth"`
}

// LoadConfig reads configuration in this order: TOML file (skipped if missing),
// defaults, environment variable overrides, then validation.
// If path is empty, it uses the PRIVX_MCP_CONFIG env var. Environment variables
// always take precedence over file values.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("PRIVX_MCP_CONFIG")
	}

	var (
		tc   tomlConfig
		meta toml.MetaData
	)

	if path != "" {
		decoded, err := toml.DecodeFile(path, &tc)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
		}

		if err == nil {
			meta = decoded
		}
	}

	cfg := tomlToConfig(&tc)
	applyDefaults(cfg, meta)
	applyEnvOverrides(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	resolvedRSAKeyFile, err := resolvePrivXSigningKeyFile(cfg.PrivXAuth.RSAKeyFile)
	if err != nil {
		return nil, err
	}

	cfg.PrivXAuth.RSAKeyFile = resolvedRSAKeyFile

	if cfg.PrivXAuth.RSAPublicKeyFile != "" {
		if err := verifyPrivXSigningKeyPair(cfg.PrivXAuth.RSAKeyFile, cfg.PrivXAuth.RSAPublicKeyFile); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// tomlToConfig converts the TOML intermediate struct to the public Config type.
func tomlToConfig(tc *tomlConfig) *Config {
	cfg := &Config{
		Server: ServerConfig{
			Name:                       tc.Server.Name,
			Version:                    tc.Server.Version,
			PublicURL:                  tc.Server.PublicURL,
			ListenAddr:                 tc.Server.ListenAddr,
			TLSCertFile:                tc.Server.TLSCert,
			TLSKeyFile:                 tc.Server.TLSKey,
			DisableLocalhostProtection: tc.Server.DisableLocalhostProtection,
			Stateless:                  tc.Server.Stateless,
			LogFile:                    tc.Server.LogFile,
			LogLevel:                   tc.Server.LogLevel,
			AuthMode:                   tc.Server.AuthMode,
			serviceSecretsRaw:          tc.Server.ServiceSecrets,
		},
		PrivXAuth: PrivXAuthConfig{
			PrivXBaseURL:         tc.PrivXAuth.PrivXBaseURL,
			PrivXJWTAudience:     tc.PrivXAuth.Audience,
			RSAKeyFile:           tc.PrivXAuth.RSAKeyFile,
			RSAPublicKeyFile:     tc.PrivXAuth.RSAPublicKeyFile,
			RSAKeyID:             tc.PrivXAuth.RSAKeyID,
			TokenIssuer:          tc.PrivXAuth.TokenIssuer,
			SubjectFormat:        tc.PrivXAuth.SubjectFormat,
			APIOAuthClientID:     tc.PrivXAuth.APIOAuthClientID,
			APIOAuthClientSecret: tc.PrivXAuth.APIOAuthClientSecret,
			APIClientID:          tc.PrivXAuth.APIClientID,
			APIClientSecret:      tc.PrivXAuth.APIClientSecret,
			CACert:               tc.PrivXAuth.CACert,
		},
		Permissions: PermissionsConfig{
			DefaultReadOnly:        tc.Permissions.DefaultReadOnly,
			Whitelist:              tc.Permissions.Whitelist,
			Blacklist:              tc.Permissions.Blacklist,
			SourceType:             tc.Permissions.SourceType,
			RequestWindowSeconds:   tc.Permissions.RequestWindowSeconds,
			MaxRequestsPerWindow:   tc.Permissions.MaxRequestsPerWindow,
			MaxedWindowWaitSeconds: tc.Permissions.MaxedWindowWaitSeconds,
		},
		OAuth: OAuthConfig{
			IssuerURL:           tc.OAuth.IssuerURL,
			Scopes:              tc.OAuth.Scopes,
			JWKSURI:             tc.OAuth.JWKSURI,
			ExpectedAudience:    tc.OAuth.Audience,
			IdentityClaimField:  tc.OAuth.IdentityClaimField,
			IdentityMappingRule: tc.OAuth.IdentityMappingRule,
			DCRStubClientID:     tc.OAuth.DCRStubClientID,
			DCRStubClientSecret: tc.OAuth.DCRStubClientSecret,
		},
	}

	parseDurationIfSet(tc.OAuth.JWKSCacheTTL, &cfg.OAuth.JWKSCacheTTL)
	parseDurationIfSet(tc.Permissions.SessionCacheTTL, &cfg.Permissions.SessionCacheTTL)
	parseDurationIfSet(tc.Permissions.RefreshCooldown, &cfg.Permissions.RefreshCooldown)

	return cfg
}

func parseDurationIfSet(s string, target *time.Duration) {
	if s == "" {
		return
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return
	}

	*target = d
}
