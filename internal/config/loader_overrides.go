package config

import (
	"os"
	"strconv"
	"strings"
)

// applyEnvOverrides overrides config fields with environment variable values.
// Env vars take precedence over TOML values. Names follow TOML sections
// (SERVER_, PRIVX_, OAUTH_, PERMISSIONS_).
func applyEnvOverrides(cfg *Config) {
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

	if v := os.Getenv("SERVER_DISABLE_LOCALHOST_PROTECTION"); v != "" {
		cfg.Server.DisableLocalhostProtection = strings.EqualFold(v, "true") || v == "1"
	}

	if v := os.Getenv("SERVER_STATELESS"); v != "" {
		cfg.Server.Stateless = strings.EqualFold(v, "true") || v == "1"
	}

	if v := os.Getenv("SERVER_AUTH_MODE"); v != "" {
		cfg.Server.AuthMode = v
	}

	if v := os.Getenv("SERVER_SERVICE_SECRETS"); v != "" {
		cfg.Server.serviceSecretsRaw = v
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
		cfg.PrivXAuth.SubjectFormat = v
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

	if v := os.Getenv("PERMISSIONS_DEFAULT_READ_ONLY"); v != "" {
		cfg.Permissions.DefaultReadOnly = strings.EqualFold(v, "true") || v == "1"
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

	parseDurationIfSet(os.Getenv("PERMISSIONS_SESSION_CACHE_TTL"), &cfg.Permissions.SessionCacheTTL)
	parseDurationIfSet(os.Getenv("PERMISSIONS_REFRESH_COOLDOWN"), &cfg.Permissions.RefreshCooldown)

	if v := os.Getenv("PERMISSIONS_REQUEST_WINDOW_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Permissions.RequestWindowSeconds = n
		}
	}

	if v := os.Getenv("PERMISSIONS_MAX_REQUESTS_PER_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Permissions.MaxRequestsPerWindow = n
		}
	}

	if v := os.Getenv("PERMISSIONS_MAXED_WINDOW_WAIT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Permissions.MaxedWindowWaitSeconds = n
		}
	}

	if v := os.Getenv("PERMISSIONS_MAXED_WINDOW_WAIT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Permissions.MaxedWindowWaitSeconds = n
		}
	}

	if v := os.Getenv("PERMISSIONS_ENABLE_SENSITIVE_DATA_TOOLS"); v != "" {
		cfg.Permissions.EnableSensitiveDataTools = strings.EqualFold(v, "true") || v == "1"
	}

	if v := os.Getenv("PERMISSIONS_SENSITIVE_DATA_TOOLS_ALLOW_NON_ADMIN"); v != "" {
		cfg.Permissions.SensitiveDataToolsAllowNonAdmin = strings.EqualFold(v, "true") || v == "1"
	}

	// OIDC provider
	if v := os.Getenv("OAUTH_ISSUER_URL"); v != "" {
		cfg.OAuth.IssuerURL = v
	}

	if v := os.Getenv("OAUTH_SCOPES"); v != "" {
		cfg.OAuth.Scopes = strings.Split(v, ",")
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
		cfg.OAuth.IdentityMappingRule = v
	}

	if v := os.Getenv("OAUTH_DCR_STUB_CLIENT_ID"); v != "" {
		cfg.OAuth.DCRStubClientID = v
	}

	if v := os.Getenv("OAUTH_DCR_STUB_CLIENT_SECRET"); v != "" {
		cfg.OAuth.DCRStubClientSecret = v
	}

	parseDurationIfSet(os.Getenv("OAUTH_JWKS_CACHE_TTL"), &cfg.OAuth.JWKSCacheTTL)
}

// splitCommaList splits a comma-separated env value into trimmed non-empty parts.
func splitCommaList(v string) []string {
	parts := strings.Split(v, ",")

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		out = append(out, part)
	}

	return out
}
