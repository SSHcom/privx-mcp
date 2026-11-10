package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// applyEnvOverrides overrides config fields with environment variable values.
// Env vars take precedence over TOML values. Names follow TOML sections
// (SERVER_, PRIVX_, OAUTH_, PERMISSIONS_).
func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv("SERVER_NAME"); v != "" {
		cfg.Server.Name = v
	}

	if v := os.Getenv("SERVER_VERSION"); v != "" {
		cfg.Server.Version = v
	}

	if v := os.Getenv("SERVER_PUBLIC_URL"); v != "" {
		cfg.Server.PublicURL = v
	}

	if v := os.Getenv("SERVER_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}

	if v := os.Getenv("SERVER_LOG_FILE"); v != "" {
		cfg.Server.LogFile = v
	}

	if v := os.Getenv("SERVER_LOG_LEVEL"); v != "" {
		cfg.Server.LogLevel = v
	}

	if v := os.Getenv("SERVER_TLS_CERT_FILE"); v != "" {
		cfg.Server.TLSCertFile = v
	}

	if v := os.Getenv("SERVER_TLS_KEY_FILE"); v != "" {
		cfg.Server.TLSKeyFile = v
	}

	if err := setBoolFromEnv("SERVER_DISABLE_LOCALHOST_PROTECTION", &cfg.Server.DisableLocalhostProtection); err != nil {
		return err
	}

	if err := setBoolFromEnv("SERVER_STATELESS", &cfg.Server.Stateless); err != nil {
		return err
	}

	if v := os.Getenv("SERVER_AUTH_MODE"); v != "" {
		cfg.Server.AuthMode = v
	}

	if v := os.Getenv("SERVER_M2M_IDENTITY_MAPPER"); v != "" {
		cfg.Server.m2mIdentityMapperRaw = v
	}

	if v := os.Getenv("SERVER_M2M_JWT_KEY"); v != "" {
		cfg.Server.m2mJWTKeyRaw = v
	}

	if v := os.Getenv("SERVER_M2M_JWT_IDENTITY_MAPPER"); v != "" {
		cfg.Server.m2mJWTIdentityMapperRaw = v
	}

	if v := os.Getenv("SERVER_M2M_JWT_ISSUER"); v != "" {
		cfg.Server.M2MJWTIssuer = v
	}

	if v := os.Getenv("PRIVX_PRIVX_BASE_URL"); v != "" {
		cfg.PrivXAuth.PrivXBaseURL = v
	}

	if v := os.Getenv("PRIVX_AUDIENCE"); v != "" {
		cfg.PrivXAuth.PrivXJWTAudience = v
	}

	if v := os.Getenv("PRIVX_RSA_KEY_FILE"); v != "" {
		cfg.PrivXAuth.RSAKeyFile = v
	}

	if v := os.Getenv("PRIVX_RSA_PUBLIC_KEY_FILE"); v != "" {
		cfg.PrivXAuth.RSAPublicKeyFile = v
	}

	if v := os.Getenv("PRIVX_RSA_KEY_ID"); v != "" {
		cfg.PrivXAuth.RSAKeyID = v
	}

	if v := os.Getenv("PRIVX_TOKEN_ISSUER"); v != "" {
		cfg.PrivXAuth.TokenIssuer = v
	}

	if v := os.Getenv("PRIVX_SUBJECT_FORMAT"); v != "" {
		cfg.PrivXAuth.SubjectFormat = strings.TrimSpace(v)
	}

	if v := os.Getenv("PRIVX_API_OAUTH_CLIENT_ID"); v != "" {
		cfg.PrivXAuth.APIOAuthClientID = v
	}

	if v := os.Getenv("PRIVX_API_OAUTH_CLIENT_SECRET"); v != "" {
		cfg.PrivXAuth.APIOAuthClientSecret = v
	}

	if v := os.Getenv("PRIVX_API_CLIENT_ID"); v != "" {
		cfg.PrivXAuth.APIClientID = v
	}

	if v := os.Getenv("PRIVX_API_CLIENT_SECRET"); v != "" {
		cfg.PrivXAuth.APIClientSecret = v
	}

	if v := os.Getenv("PRIVX_CA_CERT"); v != "" {
		cfg.PrivXAuth.CACert = v
	}

	if err := setBoolFromEnv("PERMISSIONS_DEFAULT_READ_ONLY", &cfg.Permissions.DefaultReadOnly); err != nil {
		return err
	}

	if v := os.Getenv("PERMISSIONS_SOURCE_TYPE"); v != "" {
		cfg.Permissions.SourceType = v
	}

	if v := os.Getenv("PERMISSIONS_WHITELIST"); v != "" {
		cfg.Permissions.Whitelist = splitCommaList(v)
	}

	if v := os.Getenv("PERMISSIONS_BLACKLIST"); v != "" {
		cfg.Permissions.Blacklist = splitCommaList(v)
	}

	if v := os.Getenv("PERMISSIONS_RESPONSE_FILTER"); v != "" {
		cfg.Permissions.ResponseFilter = splitCommaList(v)
	}

	if err := parseDurationIfSet(
		"permissions.session_cache_ttl",
		os.Getenv("PERMISSIONS_SESSION_CACHE_TTL"),
		&cfg.Permissions.SessionCacheTTL,
	); err != nil {
		return err
	}

	if err := parseDurationIfSet(
		"permissions.refresh_cooldown",
		os.Getenv("PERMISSIONS_REFRESH_COOLDOWN"),
		&cfg.Permissions.RefreshCooldown,
	); err != nil {
		return err
	}

	if err := setIntFromEnv("PERMISSIONS_REQUEST_WINDOW_SECONDS", &cfg.Permissions.RequestWindowSeconds); err != nil {
		return err
	}

	if err := setIntFromEnv("PERMISSIONS_MAX_REQUESTS_PER_WINDOW", &cfg.Permissions.MaxRequestsPerWindow); err != nil {
		return err
	}

	if err := setIntFromEnv("PERMISSIONS_MAXED_WINDOW_WAIT_SECONDS", &cfg.Permissions.MaxedWindowWaitSeconds); err != nil {
		return err
	}

	if err := setBoolFromEnv("PERMISSIONS_ENABLE_SENSITIVE_DATA_TOOLS", &cfg.Permissions.EnableSensitiveDataTools); err != nil {
		return err
	}

	if err := setBoolFromEnv("PERMISSIONS_SENSITIVE_DATA_TOOLS_ALLOW_NON_ADMIN", &cfg.Permissions.SensitiveDataToolsAllowNonAdmin); err != nil {
		return err
	}

	// OIDC provider
	if v := os.Getenv("OAUTH_ISSUER_URL"); v != "" {
		cfg.OAuth.IssuerURL = v
	}

	if err := setBoolFromEnv("OAUTH_ALLOW_HTTP", &cfg.OAuth.AllowHTTP); err != nil {
		return err
	}

	if v := os.Getenv("OAUTH_SCOPES"); v != "" {
		cfg.OAuth.Scopes = splitCommaList(v)
	}

	if v := os.Getenv("OAUTH_JWKS_URI"); v != "" {
		cfg.OAuth.JWKSURI = v
	}

	if v := os.Getenv("OAUTH_AUDIENCE"); v != "" {
		cfg.OAuth.ExpectedAudience = v
	}

	if v := os.Getenv("OAUTH_ID_CLAIM_FIELD"); v != "" {
		cfg.OAuth.IdentityClaimField = v
	}

	if v := os.Getenv("OAUTH_ID_MAPPING_RULE"); v != "" {
		cfg.OAuth.IdentityMappingRule = strings.TrimSpace(v)
	}

	if v := os.Getenv("OAUTH_DCR_STUB_CLIENT_ID"); v != "" {
		cfg.OAuth.DCRStubClientID = v
	}

	if v := os.Getenv("OAUTH_DCR_STUB_CLIENT_SECRET"); v != "" {
		cfg.OAuth.DCRStubClientSecret = v
	}

	if err := parseDurationIfSet(
		"oauth.jwks_cache_ttl",
		os.Getenv("OAUTH_JWKS_CACHE_TTL"),
		&cfg.OAuth.JWKSCacheTTL,
	); err != nil {
		return err
	}

	return nil
}

// setIntFromEnv applies name when it is set. An empty value leaves dest unchanged.
func setIntFromEnv(name string, dest *int) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("%s: %w (got %q)", name, err, v)
	}

	*dest = n

	return nil
}

// setBoolFromEnv applies name when it is set. An empty value leaves dest
// unchanged. An unrecognized value is an error and also leaves dest unchanged.
func setBoolFromEnv(name string, dest *bool) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}

	b, err := utils.AsBoolExtended(v)
	if err != nil {
		return fmt.Errorf("%s: %w (got %q)", name, err, v)
	}

	*dest = b

	return nil
}

// splitCommaList splits a comma-separated env value into trimmed non-empty parts.
func splitCommaList(v string) []string {
	return trimList(strings.Split(v, ","))
}
