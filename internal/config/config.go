// Package config defines the configuration types for the PrivX MCP server.
package config

import "time"

// Config is the complete server configuration.
type Config struct {
	Server      ServerConfig
	PrivXAuth   PrivXAuthConfig
	Permissions PermissionsConfig
	OAuth       OAuthConfig
}

// ServerConfig holds MCP server metadata, network settings, and TLS.
type ServerConfig struct {
	Name    string // MCP server name, default "privx-mcp-server"
	Version string // Server version

	// PublicURL is the externally reachable base URL of this server,
	// e.g. "http://localhost:8181" or "https://mcp.example.com".
	// The following URLs are derived from it:
	//   - MCP streaming endpoint: {PublicURL}/mcp
	// ListenAddr defaults to the port extracted from PublicURL when not set.
	PublicURL  string // externally reachable base URL, e.g. "http://localhost:8181"
	ListenAddr string // HTTP bind address, e.g. ":8181"; defaults to port from PublicURL

	// LogFile is the active log path. Empty writes to stdout. When set,
	// lumberjack creates/appends this file and keeps rotated backups beside it.
	LogFile string
	// LogLevel is the slog minimum level: "error", "warn", "info", or "debug".
	// Defaults to "info". Applies to the slog wrapper only.
	LogLevel string

	// TLS settings. When both TLSCertFile and TLSKeyFile are set, the server
	// starts with HTTPS (ListenAndServeTLS) instead of plain HTTP.
	TLSCertFile string // Path to TLS certificate PEM file
	TLSKeyFile  string // Path to TLS private key PEM file

	// DisableLocalhostProtection maps directly to
	// mcp.StreamableHTTPOptions.DisableLocalhostProtection. When true,
	// loopback-only host header checks are disabled.
	DisableLocalhostProtection bool

	// Stateless maps directly to mcp.StreamableHTTPOptions.Stateless. When
	// true, the streamable endpoint runs in stateless mode.
	Stateless bool

	// AuthMode is "oauth" (default) or "m2m". One process uses one mode.
	AuthMode string
	// ServiceSecrets are the parsed username-to-secret mappings for m2m.
	// The plaintext is not retained after a successful load.
	ServiceSecrets []ServiceSecret
	// serviceSecretsRaw is the TOML or env string. validate parses it and clears it.
	serviceSecretsRaw string
}

// ServiceSecret is one m2m mapping. Sum is the SHA-256 of the secret.
type ServiceSecret struct {
	Username string
	Sum      [32]byte
}

// PrivXAuthConfig holds PrivX-specific authentication settings (formerly the
// [auth] section).
type PrivXAuthConfig struct {
	PrivXBaseURL         string // Base URL of the PrivX instance
	PrivXJWTAudience     string // aud claim placed in JWTs minted for PrivX; must match the External IdP config in PrivX admin UI
	RSAKeyFile           string // Path to RSA private key file for JWT signing
	RSAPublicKeyFile     string // Optional: path to RSA public key file; when set, verified against the signing key at load time to catch local keypair drift
	RSAKeyID             string // kid header value in minted JWTs
	TokenIssuer          string // iss claim in minted JWT, default "privx-mcp"
	SubjectFormat        string // "plain" or "dn"
	APIOAuthClientID     string // OAuth client_id for API credential grant, e.g. "privx-external"
	APIOAuthClientSecret string // OAuth client_secret for API credential grant
	APIClientID          string // PrivX API client id (username in password grant)
	APIClientSecret      string // PrivX API client secret (password in password grant)
	CACert               string // Optional CA cert PEM content or file path for PrivX TLS trust
}

// PermissionsConfig holds global tool access control settings.
type PermissionsConfig struct {
	DefaultReadOnly bool // If true, deny write tools even when whitelist matches.
	// Whitelist is a prefix allow-list for tool names, e.g. ["host-", "user-", "test-"].
	// Empty means no whitelist filtering. Applied before Blacklist.
	Whitelist []string
	// Blacklist is a prefix deny-list for tool names, e.g. ["host-delete", "user-delete-"].
	// Empty means no blacklist filtering. Applied after Whitelist.
	Blacklist       []string
	SessionCacheTTL time.Duration
	// RefreshCooldown is the minimum interval between on-deny PrivX role
	// refreshes for the same identity. Zero disables on-deny refresh.
	RefreshCooldown time.Duration
	// SourceType selects which PrivX user directory to resolve identities
	// against when the same identifier exists in multiple sources
	// (e.g. "AD", "LOCAL", "MICROSOFTGRAPH").
	SourceType string

	// Per-identity tool-call rate limit (fixed window). Both must be > 0 to
	// enable; either zero disables limiting.
	RequestWindowSeconds int
	MaxRequestsPerWindow int
	// MaxedWindowWaitSeconds is extra cooldown after a window that hit
	// MaxRequestsPerWindow. Zero disables the extra wait. Must be 0 when
	// rate limiting is disabled.
	MaxedWindowWaitSeconds int

	// EnableSensitiveDataTools gates tools marked Sensitive (e.g.
	// connection-trail-get) that can surface secrets or raw session content.
	// Defaults to false: such tools are not registered at all. This key is
	// intentionally omitted from the example config and documented only in the
	// README, which warns it should be enabled only with a private/self-hosted
	// LLM.
	EnableSensitiveDataTools bool
	// SensitiveDataToolsAllowNonAdmin only has effect when
	// EnableSensitiveDataTools is true. Defaults to false: sensitive tools are
	// restricted to privx-admin role holders. When true, sensitive tools
	// instead require their own granular PrivX scopes (e.g. connections-view +
	// connections-trail), allowing suitably permissioned non-admins to use them.
	SensitiveDataToolsAllowNonAdmin bool
}

// OAuthConfig holds OIDC provider settings used by the MCP server to
// verify bearer JWTs sent to /mcp. The MCP server is a resource server only;
// it does not perform the OAuth dance itself. MCP clients (Cursor, etc.)
// obtain tokens directly from the configured upstream OIDC provider after
// discovering it via /.well-known/oauth-protected-resource.
//
// Identity mapping (formerly the [identity] section) and the DCR stub
// (formerly the [dcr] section) are merged into this section.
type OAuthConfig struct {
	IssuerURL string // OIDC discovery base URL; also the expected iss claim in tokens
	// ExpectedAudience is the expected audience (aud claim) of bearer JWTs sent
	// to /mcp.
	Scopes           []string      // optional compatibility hint for client scopes; not used for token verification
	JWKSURI          string        // Optional: override JWKS endpoint instead of auto-discovering it
	ExpectedAudience string        // expected aud claim for bearer JWTs
	JWKSCacheTTL     time.Duration // TTL for cached JWKS keys; default 1h

	// Identity mapping (formerly [identity]).
	IdentityClaimField  string // Required claim path used to derive PrivX username, e.g. "email" or "preferred_username"
	IdentityMappingRule string // "strip-domain" or "as-is"

	// DCR stub credentials (formerly [dcr]). When DCRStubClientID is set, the
	// server exposes /register and /.well-known/oauth-authorization-server
	// endpoints returning these static credentials. Allows MCP clients that
	// require DCR (e.g. Kiro) to work with IdPs that do not support it
	// (e.g. Azure Entra ID).
	DCRStubClientID     string // client_id returned to DCR callers
	DCRStubClientSecret string // client_secret returned to DCR callers (optional)
}
