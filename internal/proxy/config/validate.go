package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func validate(cfg *Config) error {
	if cfg.MCPURL == "" {
		return fmt.Errorf("mcp_url is required")
	}

	u, err := url.Parse(cfg.MCPURL)
	if err != nil {
		return fmt.Errorf("mcp_url is not a valid URL: %w", err)
	}

	if !isAbsoluteHTTPMCPURL(u) {
		return fmt.Errorf("mcp_url must be an absolute http or https URL")
	}

	if u.Scheme == "http" && !cfg.AllowHTTP && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("mcp_url uses http but allow_http is false")
	}

	level := strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	switch level {
	case "error", "warn", "info", "debug":
		cfg.LogLevel = level
	default:
		return fmt.Errorf("log_level must be one of error, warn, info, debug (got %q)", cfg.LogLevel)
	}

	if cfg.Callback.Port < 1 || cfg.Callback.Port > 65535 {
		return fmt.Errorf("callback.port must be between 1 and 65535")
	}

	if cfg.Callback.AuthTimeoutSeconds < 1 {
		return fmt.Errorf("callback.auth_timeout_seconds must be positive")
	}

	if !strings.HasPrefix(cfg.Callback.Path, "/") {
		return fmt.Errorf("callback.path must start with /")
	}

	if cfg.Client.ClientSecret != "" && cfg.Client.ClientID == "" {
		return fmt.Errorf("client.client_id is required when client.client_secret is set")
	}

	if cfg.Client.ClientID != "" && cfg.Client.ClientSecret != "" {
		switch cfg.Client.TokenEndpointAuthMethod {
		case "client_secret_post", "client_secret_basic":
		default:
			return fmt.Errorf("client.token_endpoint_auth_method must be client_secret_post or client_secret_basic when a confidential client is configured")
		}
	}

	return nil
}

func isAbsoluteHTTPMCPURL(u *url.URL) bool {
	if u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return false
	}

	return u.Scheme == "http" || u.Scheme == "https"
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback()
}
