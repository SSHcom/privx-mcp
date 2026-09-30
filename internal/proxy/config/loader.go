package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

type tomlConfig struct {
	MCPURL    string `toml:"mcp_url"`
	AllowHTTP bool   `toml:"allow_http"`
	LogLevel  string `toml:"log_level"`
	LogFile   string `toml:"log_file"`

	Callback struct {
		Host               string `toml:"host"`
		Port               int    `toml:"port"`
		Path               string `toml:"path"`
		AuthTimeoutSeconds int    `toml:"auth_timeout_seconds"`
	} `toml:"callback"`

	Client struct {
		ClientID                string   `toml:"client_id"`
		ClientSecret            string   `toml:"client_secret"`
		Scopes                  []string `toml:"scopes"`
		TokenEndpointAuthMethod string   `toml:"token_endpoint_auth_method"`
	} `toml:"client"`
}

// Load reads configuration from path, applies defaults, then validates.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config file path is required")
	}

	var tc tomlConfig

	if _, err := toml.DecodeFile(path, &tc); err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	cfg := tomlToConfig(&tc)
	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func tomlToConfig(tc *tomlConfig) *Config {
	scopes := tc.Client.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	return &Config{
		MCPURL:    strings.TrimSpace(tc.MCPURL),
		AllowHTTP: tc.AllowHTTP,
		LogLevel:  strings.TrimSpace(tc.LogLevel),
		LogFile:   strings.TrimSpace(tc.LogFile),
		Callback: CallbackConfig{
			Host:               strings.TrimSpace(tc.Callback.Host),
			Port:               tc.Callback.Port,
			Path:               strings.TrimSpace(tc.Callback.Path),
			AuthTimeoutSeconds: tc.Callback.AuthTimeoutSeconds,
		},
		Client: ClientConfig{
			ClientID:                strings.TrimSpace(tc.Client.ClientID),
			ClientSecret:            tc.Client.ClientSecret,
			Scopes:                  scopes,
			TokenEndpointAuthMethod: strings.TrimSpace(tc.Client.TokenEndpointAuthMethod),
		},
	}
}

func applyDefaults(cfg *Config) {
	if cfg.LogLevel == "" {
		cfg.LogLevel = defaultLogLevel
	}

	if cfg.Callback.Host == "" {
		cfg.Callback.Host = defaultCallbackHost
	}

	if cfg.Callback.Port == 0 {
		cfg.Callback.Port = defaultCallbackPort
	}

	if cfg.Callback.Path == "" {
		cfg.Callback.Path = defaultCallbackPath
	}

	if cfg.Callback.AuthTimeoutSeconds == 0 {
		cfg.Callback.AuthTimeoutSeconds = defaultAuthTimeout
	}

	if cfg.Client.Scopes == nil {
		cfg.Client.Scopes = []string{}
	}
}
