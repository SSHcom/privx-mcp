package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// DiscoveryDocument contains only the OIDC discovery fields this server
// consumes during bootstrap.
type DiscoveryDocument struct {
	Issuer  string
	JWKSURI string
}

// HTTPDiscoveryClient fetches OIDC discovery metadata from the provider issuer URL.
type HTTPDiscoveryClient struct {
	client    *http.Client
	allowHTTP bool
}

// NewHTTPDiscoveryClient creates a discovery client. A nil client uses one that
// rejects non-loopback http unless allowHTTP is set, and refuses a redirect to
// another host.
func NewHTTPDiscoveryClient(client *http.Client, allowHTTP bool) *HTTPDiscoveryClient {
	if client == nil {
		client = utils.NewHTTPClient(allowHTTP)
	}

	return &HTTPDiscoveryClient{client: client, allowHTTP: allowHTTP}
}

// Fetch resolves OIDC discovery metadata from /.well-known/openid-configuration.
// The returned issuer is issuerURL. The document's issuer must match it, aside
// from one trailing slash. jwks_uri must be an absolute http or https URL, and
// plain HTTP is limited to loopback unless allowHTTP was set.
func (c *HTTPDiscoveryClient) Fetch(ctx context.Context, issuerURL string) (*DiscoveryDocument, error) {
	issuerURL = strings.TrimSpace(issuerURL)
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required")
	}

	if _, err := utils.RequireHTTPURL(issuerURL, c.allowHTTP); err != nil {
		return nil, fmt.Errorf("issuer URL: %w", err)
	}

	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.Request != nil && resp.Request.URL != nil {
		if _, err := utils.RequireHTTPURL(resp.Request.URL.String(), c.allowHTTP); err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}

		if !utils.SameRedirectHost(req.URL, resp.Request.URL) {
			return nil, fmt.Errorf("discovery redirected from %q to %q", req.URL.String(), resp.Request.URL.String())
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("discovery request returned status %d", resp.StatusCode)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if err := validateDiscoveredIssuer(doc.Issuer, issuerURL); err != nil {
		return nil, err
	}

	if _, err := utils.RequireHTTPURL(doc.JWKSURI, c.allowHTTP); err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}

	return &DiscoveryDocument{
		Issuer:  issuerURL,
		JWKSURI: doc.JWKSURI,
	}, nil
}

func validateDiscoveredIssuer(got, want string) error {
	if strings.TrimSpace(got) == "" {
		return fmt.Errorf("discovery document missing issuer")
	}

	if !issuersEqual(got, want) {
		return fmt.Errorf(
			"discovery issuer %q does not match oauth.issuer_url %q",
			strings.TrimSpace(got),
			strings.TrimSpace(want),
		)
	}

	return nil
}

// issuersEqual compares issuer identifiers, ignoring one trailing slash.
func issuersEqual(a, b string) bool {
	return strings.TrimSuffix(strings.TrimSpace(a), "/") == strings.TrimSuffix(strings.TrimSpace(b), "/")
}
