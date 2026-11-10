package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
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

		AuthMode             string `toml:"auth_mode"`
		M2MIdentityMapper    string `toml:"m2m_identity_mapper"`
		M2MJWTKey            string `toml:"m2m_jwt_key"`
		M2MJWTIdentityMapper string `toml:"m2m_jwt_identity_mapper"`
		M2MJWTIssuer         string `toml:"m2m_jwt_issuer"`
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
		ResponseFilter         []string `toml:"response_filter"`
		SessionCacheTTL        string   `toml:"session_cache_ttl"`
		RefreshCooldown        string   `toml:"refresh_cooldown"`
		SourceType             string   `toml:"source_type"`
		RequestWindowSeconds   int      `toml:"request_window_seconds"`
		MaxRequestsPerWindow   int      `toml:"max_requests_per_window"`
		MaxedWindowWaitSeconds int      `toml:"maxed_window_wait_seconds"`
		// Intentionally undocumented in the example config; see security.md.
		EnableSensitiveDataTools        bool `toml:"enable_sensitive_data_tools"`
		SensitiveDataToolsAllowNonAdmin bool `toml:"sensitive_data_tools_allow_non_admin"`
	} `toml:"permissions"`

	OAuth struct {
		IssuerURL    string   `toml:"issuer_url"`
		AllowHTTP    bool     `toml:"allow_http"`
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

	cfg, err := tomlToConfig(&tc)
	if err != nil {
		return nil, err
	}

	applyDefaults(cfg, meta)

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}

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
func tomlToConfig(tc *tomlConfig) (*Config, error) {
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
			m2mIdentityMapperRaw:       tc.Server.M2MIdentityMapper,
			m2mJWTKeyRaw:               tc.Server.M2MJWTKey,
			m2mJWTIdentityMapperRaw:    tc.Server.M2MJWTIdentityMapper,
			M2MJWTIssuer:               tc.Server.M2MJWTIssuer,
		},
		PrivXAuth: PrivXAuthConfig{
			PrivXBaseURL:         tc.PrivXAuth.PrivXBaseURL,
			PrivXJWTAudience:     tc.PrivXAuth.Audience,
			RSAKeyFile:           tc.PrivXAuth.RSAKeyFile,
			RSAPublicKeyFile:     tc.PrivXAuth.RSAPublicKeyFile,
			RSAKeyID:             tc.PrivXAuth.RSAKeyID,
			TokenIssuer:          tc.PrivXAuth.TokenIssuer,
			SubjectFormat:        strings.TrimSpace(tc.PrivXAuth.SubjectFormat),
			APIOAuthClientID:     tc.PrivXAuth.APIOAuthClientID,
			APIOAuthClientSecret: tc.PrivXAuth.APIOAuthClientSecret,
			APIClientID:          tc.PrivXAuth.APIClientID,
			APIClientSecret:      tc.PrivXAuth.APIClientSecret,
			CACert:               tc.PrivXAuth.CACert,
		},
		Permissions: PermissionsConfig{
			DefaultReadOnly:        tc.Permissions.DefaultReadOnly,
			Whitelist:              trimList(tc.Permissions.Whitelist),
			Blacklist:              trimList(tc.Permissions.Blacklist),
			ResponseFilter:         trimList(tc.Permissions.ResponseFilter),
			SourceType:             tc.Permissions.SourceType,
			RequestWindowSeconds:   tc.Permissions.RequestWindowSeconds,
			MaxRequestsPerWindow:   tc.Permissions.MaxRequestsPerWindow,
			MaxedWindowWaitSeconds: tc.Permissions.MaxedWindowWaitSeconds,

			EnableSensitiveDataTools:        tc.Permissions.EnableSensitiveDataTools,
			SensitiveDataToolsAllowNonAdmin: tc.Permissions.SensitiveDataToolsAllowNonAdmin,
		},
		OAuth: OAuthConfig{
			IssuerURL:           tc.OAuth.IssuerURL,
			AllowHTTP:           tc.OAuth.AllowHTTP,
			Scopes:              trimList(tc.OAuth.Scopes),
			JWKSURI:             tc.OAuth.JWKSURI,
			ExpectedAudience:    tc.OAuth.Audience,
			IdentityClaimField:  tc.OAuth.IdentityClaimField,
			IdentityMappingRule: strings.TrimSpace(tc.OAuth.IdentityMappingRule),
			DCRStubClientID:     tc.OAuth.DCRStubClientID,
			DCRStubClientSecret: tc.OAuth.DCRStubClientSecret,
		},
	}

	if err := parseDurationIfSet(
		"oauth.jwks_cache_ttl",
		tc.OAuth.JWKSCacheTTL,
		&cfg.OAuth.JWKSCacheTTL,
	); err != nil {
		return nil, err
	}

	if err := parseDurationIfSet(
		"permissions.session_cache_ttl",
		tc.Permissions.SessionCacheTTL,
		&cfg.Permissions.SessionCacheTTL,
	); err != nil {
		return nil, err
	}

	if err := parseDurationIfSet(
		"permissions.refresh_cooldown",
		tc.Permissions.RefreshCooldown,
		&cfg.Permissions.RefreshCooldown,
	); err != nil {
		return nil, err
	}

	return cfg, nil
}

// trimList drops blank entries and trims the rest. A nil or empty input is returned unchanged.
func trimList(items []string) []string {
	if len(items) == 0 {
		return items
	}

	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		out = append(out, item)
	}

	return out
}

// parseDurationIfSet parses raw into target when it is set.
// A bare "0" is accepted because session_cache_ttl and refresh_cooldown use it
// to disable the feature, and time.ParseDuration requires a unit.
func parseDurationIfSet(field, raw string, target *time.Duration) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}

	if s == "0" {
		*target = 0
		return nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, raw, err)
	}

	*target = d

	return nil
}
