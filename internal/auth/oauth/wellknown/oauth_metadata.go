package wellknown

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OAuthMetadataURL is the RFC 8414 endpoint for authorization server metadata.
const OAuthMetadataURL = "/.well-known/oauth-authorization-server"

// OAuthMetadataConfig configures the proxied authorization server metadata.
type OAuthMetadataConfig struct {
	// PublicURL is this server's public URL, used for the registration_endpoint.
	PublicURL string

	// UpstreamIssuerURL is the real IdP issuer URL whose metadata we proxy.
	UpstreamIssuerURL string

	// Scopes are advertised as scopes_supported so MCP clients include a
	// non-empty scope in their authorization request. Entra ID v2 rejects
	// authorize/token requests that omit the scope parameter (AADSTS900144).
	Scopes []string
}

// RegisterOAuthMetadata mounts a /.well-known/oauth-authorization-server
// endpoint that proxies the upstream IdP's OIDC discovery metadata and injects
// a registration_endpoint pointing to this server's /register stub.
func RegisterOAuthMetadata(mux *http.ServeMux, cfg OAuthMetadataConfig) error {
	if mux == nil {
		return fmt.Errorf("oauth metadata mux is required")
	}

	if cfg.PublicURL == "" {
		return fmt.Errorf("oauth metadata public_url is required")
	}

	if cfg.UpstreamIssuerURL == "" {
		return fmt.Errorf("oauth metadata upstream_issuer_url is required")
	}

	mux.HandleFunc(OAuthMetadataURL, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		metadata, err := fetchUpstreamMetadata(r.Context(), cfg.UpstreamIssuerURL)
		if err != nil {
			http.Error(w, "failed to fetch upstream metadata", http.StatusBadGateway)
			return
		}

		// Present this server as the issuer. RFC 8414 §3.3 requires the
		// issuer in the metadata to match the authorization-server identifier
		// the client used to build the well-known URL. The protected-resource
		// metadata advertises this server's PublicURL as the authorization
		// server (so DCR routes through our /register stub), so the issuer
		// must be PublicURL — not the upstream Entra issuer, which would make
		// spec-compliant clients (Kiro) reject the metadata with an issuer
		// mismatch.
		metadata["issuer"] = cfg.PublicURL

		// Inject our local registration endpoint.
		metadata["registration_endpoint"] = cfg.PublicURL + "/register"

		// Ensure PKCE support is advertised. MCP clients (Kiro) require
		// code_challenge_methods_supported to include S256.
		if _, ok := metadata["code_challenge_methods_supported"]; !ok {
			metadata["code_challenge_methods_supported"] = []string{"S256"}
		}

		// Ensure grant_types_supported is present.
		if _, ok := metadata["grant_types_supported"]; !ok {
			metadata["grant_types_supported"] = []string{"authorization_code", "refresh_token"}
		}

		// Advertise the configured scopes. When set, cfg.Scopes includes the
		// resource API scope the client must request to get a token with the
		// correct audience; it must OVERRIDE the upstream provider's generic
		// scopes_supported (Entra always sends openid/profile/email/
		// offline_access, which omit the API scope). Without this, clients
		// send an authorize request with no usable scope and Entra rejects it
		// (AADSTS900144). Fall back to upstream only when no scopes are
		// configured.
		if len(cfg.Scopes) > 0 {
			metadata["scopes_supported"] = cfg.Scopes
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(metadata)
	})

	return nil
}

func fetchUpstreamMetadata(ctx context.Context, issuerURL string) (map[string]any, error) {
	// Build discovery URL candidates. For Azure v1 issuers
	// (sts.windows.net/{tenant}) we also try the v2 discovery endpoint
	// (login.microsoftonline.com/{tenant}/v2.0) because MCP clients like
	// Kiro require v2 OAuth endpoints with PKCE support.
	urls := buildDiscoveryURLs(issuerURL)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}

		body, readErr := io.ReadAll(resp.Body)

		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		var metadata map[string]any
		if err := json.Unmarshal(body, &metadata); err != nil {
			continue
		}

		return metadata, nil
	}

	return nil, fmt.Errorf("could not fetch metadata from %s", issuerURL)
}

// buildDiscoveryURLs returns discovery endpoints to try in priority order.
// For Azure v1 issuers (https://sts.windows.net/{tenant}/), the v2 endpoint
// is preferred because it advertises PKCE-compatible OAuth 2.0 endpoints.
func buildDiscoveryURLs(issuerURL string) []string {
	urls := []string{}

	// Try to derive the Azure v2 discovery URL from a v1 issuer.
	if strings.Contains(issuerURL, "sts.windows.net") {
		// Extract tenant ID from https://sts.windows.net/{tenant}/
		trimmed := strings.TrimRight(issuerURL, "/")

		parts := strings.Split(trimmed, "/")
		if len(parts) > 0 {
			tenantID := parts[len(parts)-1]
			v2URL := "https://login.microsoftonline.com/" + tenantID + "/v2.0/.well-known/openid-configuration"
			urls = append(urls, v2URL)
		}
	}

	// Standard OIDC and RFC 8414 discovery.
	urls = append(urls,
		issuerURL+"/.well-known/openid-configuration",
		issuerURL+"/.well-known/oauth-authorization-server",
	)

	return urls
}
