package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// validate checks that all required configuration fields are set and returns
// an error naming any missing fields.
func validate(cfg *Config) error {
	var missing []string

	if cfg.PrivXAuth.PrivXBaseURL == "" {
		missing = append(missing, "privx_auth.privx_base_url")
	}

	if cfg.PrivXAuth.RSAKeyFile == "" {
		missing = append(missing, "privx_auth.rsa_key_file")
	}

	if cfg.PrivXAuth.RSAKeyID == "" {
		missing = append(missing, "privx_auth.rsa_key_id")
	}

	if cfg.Permissions.SourceType == "" {
		missing = append(missing, "permissions.source_type")
	}

	mode := cfg.Server.AuthMode
	if mode == "" {
		mode = "oauth"
	}

	switch mode {
	case "oauth":
		if cfg.OAuth.IssuerURL == "" {
			missing = append(missing, "oauth.issuer_url")
		}

		if cfg.OAuth.ExpectedAudience == "" {
			missing = append(missing, "oauth.audience")
		}
	case "m2m":
	default:
		return fmt.Errorf("server.auth_mode must be oauth or m2m (got %q)", cfg.Server.AuthMode)
	}

	if cfg.Server.PublicURL == "" {
		missing = append(missing, "server.public_url")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration fields: %s", strings.Join(missing, ", "))
	}

	level := strings.ToLower(strings.TrimSpace(cfg.Server.LogLevel))
	switch level {
	case "", "error", "warn", "info", "debug":
		if level != "" {
			cfg.Server.LogLevel = level
		}
	default:
		return fmt.Errorf("server.log_level must be one of error, warn, info, debug (got %q)", cfg.Server.LogLevel)
	}

	if cfg.Permissions.SessionCacheTTL < 0 {
		return fmt.Errorf("permissions.session_cache_ttl must be non-negative")
	}

	if cfg.Permissions.RefreshCooldown < 0 {
		return fmt.Errorf("permissions.refresh_cooldown must be non-negative")
	}

	if cfg.Permissions.RequestWindowSeconds < 0 {
		return fmt.Errorf("permissions.request_window_seconds must be non-negative")
	}

	if cfg.Permissions.MaxRequestsPerWindow < 0 {
		return fmt.Errorf("permissions.max_requests_per_window must be non-negative")
	}

	if cfg.Permissions.MaxedWindowWaitSeconds < 0 {
		return fmt.Errorf("permissions.maxed_window_wait_seconds must be non-negative")
	}

	windowSet := cfg.Permissions.RequestWindowSeconds > 0

	maxSet := cfg.Permissions.MaxRequestsPerWindow > 0
	if windowSet != maxSet {
		return fmt.Errorf("permissions.request_window_seconds and permissions.max_requests_per_window must both be set (> 0) or both be zero")
	}

	if cfg.Permissions.MaxedWindowWaitSeconds > 0 && (!windowSet || !maxSet) {
		return fmt.Errorf("permissions.maxed_window_wait_seconds requires permissions.request_window_seconds and permissions.max_requests_per_window to be set (> 0)")
	}

	waitWithoutRateLimit := cfg.Permissions.MaxedWindowWaitSeconds > 0 && (!windowSet || !maxSet)
	if waitWithoutRateLimit {
		return fmt.Errorf("permissions.maxed_window_wait_seconds requires permissions.request_window_seconds and permissions.max_requests_per_window to be set (> 0)")
	}

	// TLS / public_url scheme consistency.
	// TLS cert and key must be configured together: a half-set pair is almost
	// always a mistake (one forgotten), and ListenAndServeTLS in main only
	// activates when both are set, so a lone value would otherwise be silently
	// ignored.
	tlsCert, tlsKey := cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile

	tlsPairIncomplete := (tlsCert == "") != (tlsKey == "")
	if tlsPairIncomplete {
		return fmt.Errorf(
			"server.tls_cert_file and server.tls_key_file must be set together (got cert=%q key=%q)",
			tlsCert, tlsKey,
		)
	}

	// When TLS is configured on the server itself, verify the cert and key
	// files exist so misconfigurations (e.g. a wrong path) surface at config
	// load rather than failing at startup with an opaque ListenAndServeTLS
	// error. Also enforce that the advertised public_url is https://: it is
	// published verbatim in OAuth metadata
	// (/.well-known/oauth-protected-resource and the DCR stub), where a
	// non-https URL is rejected by MCP clients. The reverse direction is NOT
	// enforced: a https:// public_url with no tls_* vars is a valid
	// TLS-terminated-at-proxy deployment that cannot be distinguished from a
	// misconfiguration using config alone.
	tlsConfigured := tlsCert != "" && tlsKey != ""
	if tlsConfigured {
		if !utils.FileExists(tlsCert) {
			return fmt.Errorf("server.tls_cert_file not found: %q", tlsCert)
		}

		if !utils.FileExists(tlsKey) {
			return fmt.Errorf("server.tls_key_file not found: %q", tlsKey)
		}

		if cfg.Server.PublicURL != "" && !strings.HasPrefix(strings.ToLower(cfg.Server.PublicURL), "https://") {
			return fmt.Errorf(
				"server.public_url must use https:// when server.tls_cert_file and server.tls_key_file are set (got %q)",
				cfg.Server.PublicURL,
			)
		}
	}

	if err := applyServiceSecrets(cfg); err != nil {
		return err
	}

	switch mode {
	case "oauth":
		if len(cfg.Server.ServiceSecrets) > 0 {
			return fmt.Errorf("server.service_secrets must be empty when server.auth_mode is oauth")
		}
	case "m2m":
		if len(cfg.Server.ServiceSecrets) == 0 {
			return fmt.Errorf("server.service_secrets is required when server.auth_mode is m2m")
		}

		if err := oauthFieldsSetInM2M(cfg); err != nil {
			return err
		}

		if err := validateM2MPublicURL(cfg.Server.PublicURL); err != nil {
			return err
		}
	}

	return nil
}

// PublicURLIsHTTPS reports whether raw is an https URL with a host.
func PublicURLIsHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "https") && u.Hostname() != ""
}

func oauthFieldsSetInM2M(cfg *Config) error {
	set := []string{}
	if cfg.OAuth.IssuerURL != "" {
		set = append(set, "oauth.issuer_url")
	}

	if cfg.OAuth.ExpectedAudience != "" {
		set = append(set, "oauth.audience")
	}

	if cfg.OAuth.JWKSURI != "" {
		set = append(set, "oauth.jwks_uri")
	}

	if len(cfg.OAuth.Scopes) > 0 {
		set = append(set, "oauth.scopes")
	}

	if cfg.OAuth.DCRStubClientID != "" {
		set = append(set, "oauth.dcr_stub_client_id")
	}

	if cfg.OAuth.DCRStubClientSecret != "" {
		set = append(set, "oauth.dcr_stub_client_secret")
	}

	if len(set) == 0 {
		return nil
	}

	return fmt.Errorf("%s must be empty when server.auth_mode is m2m", strings.Join(set, ", "))
}

func validateM2MPublicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("server.public_url %q is not a valid URL", raw)
	}

	switch strings.ToLower(u.Scheme) {
	case "https", "http":
		return nil
	default:
		return fmt.Errorf("server.public_url must use http or https when server.auth_mode is m2m (got %q)", raw)
	}
}
