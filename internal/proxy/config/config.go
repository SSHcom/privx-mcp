// Package config loads and validates the PrivX MCP stdio proxy TOML file.
package config

const (
	defaultCallbackHost = "localhost"
	defaultCallbackPath = "/oauth/callback"
	defaultCallbackPort = 3334
	defaultAuthTimeout  = 60
	defaultLogLevel     = "info"
)

// Config is the complete proxy configuration.
type Config struct {
	MCPURL    string
	AllowHTTP bool
	LogLevel  string
	LogFile   string
	Callback  CallbackConfig
	Client    ClientConfig
}

// CallbackConfig is the loopback OAuth callback listener.
type CallbackConfig struct {
	Host               string
	Port               int
	Path               string
	AuthTimeoutSeconds int
}

// ClientConfig is the static OAuth client identity.
type ClientConfig struct {
	ClientID                string
	ClientSecret            string
	Scopes                  []string
	TokenEndpointAuthMethod string
}
