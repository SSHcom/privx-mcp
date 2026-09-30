package config

import (
	"net/url"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/pmsshintegration/privx-mcp/internal/version"
)

func applyDefaults(cfg *Config, meta toml.MetaData) {
	applyServerDefaults(cfg, meta)
	applyPrivXAuthDefaults(cfg)
	applyOAuthDefaults(cfg)
	applyPermissionsDefaults(cfg, meta)
}

// apply<Section>Defaults sets default values for fields that are not yet configured.

func applyServerDefaults(cfg *Config, meta toml.MetaData) {
	if cfg.Server.Name == "" {
		cfg.Server.Name = "privx-mcp-server"
	}

	if cfg.Server.Version == "" {
		cfg.Server.Version = version.MustComponent(version.Server, version.ServerBinary)
	}

	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = listenAddrFromPublicURL(cfg.Server.PublicURL)
	}

	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}

	if cfg.Server.AuthMode == "" {
		cfg.Server.AuthMode = "oauth"
	}

	if !meta.IsDefined("server", "stateless") {
		cfg.Server.Stateless = true
	}
}

// listenAddrFromPublicURL derives a ":port" bind address from the port in publicURL.
// Falls back to ":8181" if the URL cannot be parsed or carries no explicit port.
func listenAddrFromPublicURL(publicURL string) string {
	if publicURL != "" {
		if u, err := url.Parse(publicURL); err == nil {
			if p := u.Port(); p != "" {
				return ":" + p
			}
		}
	}

	return ":8181"
}

func applyPrivXAuthDefaults(cfg *Config) {
	if cfg.PrivXAuth.TokenIssuer == "" {
		cfg.PrivXAuth.TokenIssuer = "privx-mcp"
	}

	if cfg.PrivXAuth.SubjectFormat == "" {
		cfg.PrivXAuth.SubjectFormat = "plain"
	}
}

func applyOAuthDefaults(cfg *Config) {
	if cfg.OAuth.JWKSCacheTTL == 0 {
		cfg.OAuth.JWKSCacheTTL = time.Hour
	}

	if cfg.OAuth.IdentityClaimField == "" {
		cfg.OAuth.IdentityClaimField = "email"
	}

	if cfg.OAuth.IdentityMappingRule == "" {
		cfg.OAuth.IdentityMappingRule = "as-is"
	}
}

func applyPermissionsDefaults(cfg *Config, meta toml.MetaData) {
	if !meta.IsDefined("permissions", "default_read_only") {
		cfg.Permissions.DefaultReadOnly = true
	}

	if !meta.IsDefined("permissions", "session_cache_ttl") {
		cfg.Permissions.SessionCacheTTL = 30 * time.Second
	}

	if !meta.IsDefined("permissions", "refresh_cooldown") {
		cfg.Permissions.RefreshCooldown = time.Minute
	}
}
