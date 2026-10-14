package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/m2m"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth/wellknown"
	"github.com/pmsshintegration/privx-mcp/internal/auth/privx"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/runtime"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/transport"
	httpservice "github.com/pmsshintegration/privx-mcp/internal/service/http"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
	"github.com/pmsshintegration/privx-mcp/internal/tools"
)

var connectWithAPICredentials = privx.ConnectWithAPICredentials

// NewServer builds the shared HTTP server and returns a shutdown cleanup function.
func NewServer(configPath string) (*http.Server, func(), error) {
	// Load the configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, nil, err
	}

	return NewServerFromConfig(cfg)
}

// NewServerFromConfig builds the shared HTTP server from an already-loaded
// configuration and returns a shutdown cleanup function.
func NewServerFromConfig(cfg *config.Config) (*http.Server, func(), error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config is required")
	}

	permissionsConnector, err := connectWithAPICredentials(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize PrivX permission connector: %w", err)
	}

	// Build the identity verifier used at the HTTP edge to gate /mcp.
	verifier, err := buildIdentityVerifier(cfg)
	if err != nil {
		return nil, nil, err
	}

	logIdentityVerifier(cfg)
	logSensitiveDataTools(cfg)

	// Build the runtime core. Token verification happens at the edge; the
	// authenticator consumes already-verified claims from request context.
	core := buildRuntimeCore(
		cfg,
		auth.NewAuthenticator(cfg),
		transport.HTTPClaimsSource{},
		runtime.NewPermissionEngineWithClient(
			permissionsConnector,
			runtime.WithSessionService(session.NewService(cfg.Permissions.SessionCacheTTL), cfg.PrivXAuth.PrivXBaseURL),
			runtime.WithSourceType(cfg.Permissions.SourceType),
			runtime.WithRefreshCooldown(cfg.Permissions.RefreshCooldown),
		),
	)

	// Build the HTTP mux. Authorization is delegated to the configured
	// upstream OIDC provider: /mcp verifies bearer JWTs at the edge and
	// /.well-known/oauth-protected-resource advertises which issuer to use.
	// The MCP server acts as a resource server only; clients perform the
	// browser-based OAuth flow directly with the provider.
	registrars := []httpservice.RouteRegistrar{}
	if cfg.Server.AuthMode != "m2m" {
		registrars = append(registrars,
			func(m *http.ServeMux) error {
				authServer := cfg.OAuth.IssuerURL
				if cfg.OAuth.DCRStubClientID != "" {
					authServer = cfg.Server.PublicURL
				}

				return wellknown.RegisterRoutes(m, wellknown.ProtectedResourceConfig{
					Resource:             cfg.Server.PublicURL + "/mcp",
					AuthorizationServers: []string{authServer},
				})
			},
			func(m *http.ServeMux) error {
				if cfg.OAuth.DCRStubClientID == "" {
					return nil
				}

				return wellknown.RegisterDCRStub(m, wellknown.DCRStubConfig{
					ClientID:     cfg.OAuth.DCRStubClientID,
					ClientSecret: cfg.OAuth.DCRStubClientSecret,
					Scopes:       cfg.OAuth.Scopes,
				})
			},
			func(m *http.ServeMux) error {
				if cfg.OAuth.DCRStubClientID == "" {
					return nil
				}

				return wellknown.RegisterOAuthMetadata(m, wellknown.OAuthMetadataConfig{
					PublicURL:         cfg.Server.PublicURL,
					UpstreamIssuerURL: cfg.OAuth.IssuerURL,
					Scopes:            cfg.OAuth.Scopes,
				})
			},
		)
	}

	registrars = append(registrars, func(m *http.ServeMux) error {
		return transport.RegisterRoutes(m, core, transport.StreamConfig{
			PublicURL:                  cfg.Server.PublicURL,
			Verifier:                   verifier,
			DisableLocalhostProtection: cfg.Server.DisableLocalhostProtection,
			Stateless:                  cfg.Server.Stateless,
		})
	})

	mux, err := httpservice.NewMux(registrars...)
	if err != nil {
		verifier.Close()
		return nil, nil, err
	}

	server, closeServer, err := httpservice.NewHTTPServer(httpservice.Options{
		Addr:              cfg.Server.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ShutdownTimeout:   5 * time.Second,
	})
	if err != nil {
		verifier.Close()
		return nil, nil, err
	}

	cleanup := func() {
		closeServer()
		verifier.Close()
	}

	return server, cleanup, nil
}

// buildRuntimeCore constructs the transport-agnostic MCP runtime. Token
// verification is performed at the HTTP edge (see transport.WithBearerVerification);
// the authenticator only consumes already-verified claims.
func buildRuntimeCore(cfg *config.Config, authenticator auth.Authenticator, claimsSource runtime.ClaimsSource, permissionOverride ...*runtime.PermissionEngine) *runtime.Core {
	reg := registry.NewRegistry()
	tools.Register(reg, cfg)

	permissions := runtime.NewPermissionEngine()
	if len(permissionOverride) > 0 && permissionOverride[0] != nil {
		permissions = permissionOverride[0]
	}

	return runtime.NewCore(
		cfg.Server,
		authenticator,
		reg,
		permissions,
		claimsSource,
		runtime.WithRateLimiter(
			session.NewRateLimiter(
				cfg.Permissions.RequestWindowSeconds,
				cfg.Permissions.MaxRequestsPerWindow,
				cfg.Permissions.MaxedWindowWaitSeconds,
			),
			cfg.PrivXAuth.PrivXBaseURL,
		),
	)
}

// identityVerifier is the HTTP-edge bearer check. OAuth uses JWKS; m2m uses service secrets.
type identityVerifier interface {
	Verify(ctx context.Context, raw string) (*oauth.IdentityClaims, error)
	Close()
}

func buildIdentityVerifier(cfg *config.Config) (identityVerifier, error) {
	if cfg.Server.AuthMode == "m2m" {
		return m2m.NewVerifier(cfg.Server.ServiceSecrets), nil
	}

	provider := cfg.OAuth

	issuerURL, jwksURI, err := resolveVerifierEndpoints(provider.IssuerURL, provider.JWKSURI)
	if err != nil {
		return nil, err
	}

	return oauth.NewJWKSTokenVerifier(oauth.JWKSTokenVerifierConfig{
		JWKSURI:          jwksURI,
		ExpectedIssuer:   issuerURL,
		ExpectedAudience: provider.ExpectedAudience,
		CacheTTL:         provider.JWKSCacheTTL,
	})
}

func resolveVerifierEndpoints(issuerURL, jwksURI string) (string, string, error) {
	if jwksURI != "" {
		return issuerURL, jwksURI, nil
	}

	discoveredIssuer, discoveredJWKS, err := discoverJWKSURI(issuerURL)
	if err != nil {
		return "", "", err
	}

	if discoveredIssuer != "" {
		issuerURL = discoveredIssuer
	}

	return issuerURL, discoveredJWKS, nil
}

func logIdentityVerifier(cfg *config.Config) {
	usernames := make([]string, len(cfg.Server.ServiceSecrets))
	for i, secret := range cfg.Server.ServiceSecrets {
		usernames[i] = secret.Username
	}

	logging.Info(
		"identity verifier ready",
		"auth_mode", cfg.Server.AuthMode,
		"service_secrets", len(usernames),
		"usernames", usernames,
	)
}

// logSensitiveDataTools emits a startup warning when the sensitive-data tool
// gate is open, so an operator can see in the logs that tools which may expose
// secrets or raw session content are registered, and in which access mode.
func logSensitiveDataTools(cfg *config.Config) {
	if !cfg.Permissions.EnableSensitiveDataTools {
		if cfg.Permissions.SensitiveDataToolsAllowNonAdmin {
			logging.Warn(
				"permissions.sensitive_data_tools_allow_non_admin is set but has no effect " +
					"because permissions.enable_sensitive_data_tools is false",
			)
		}

		return
	}

	access := "privx-admin only"
	if cfg.Permissions.SensitiveDataToolsAllowNonAdmin {
		access = "any user with the tool's granular PrivX permissions"
	}

	logging.Warn(
		"sensitive-data tools are ENABLED; these can expose secrets and raw session content. "+
			"Enable only with a private/self-hosted LLM you control.",
		"access", access,
	)
}

func discoverJWKSURI(issuerURL string) (string, string, error) {
	if issuerURL == "" {
		return "", "", fmt.Errorf("oauth.issuer_url is required")
	}

	discoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	discoveryDoc, err := oauth.NewHTTPDiscoveryClient(nil).Fetch(discoveryCtx, issuerURL)
	if err != nil {
		return "", "", fmt.Errorf("fetch provider discovery document: %w", err)
	}

	return discoveryDoc.Issuer, discoveryDoc.JWKSURI, nil
}
