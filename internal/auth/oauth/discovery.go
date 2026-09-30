package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DiscoveryDocument contains only the OIDC discovery fields this server
// consumes during bootstrap.
type DiscoveryDocument struct {
	Issuer  string
	JWKSURI string
}

// HTTPDiscoveryClient fetches OIDC discovery metadata from the provider issuer URL.
type HTTPDiscoveryClient struct {
	client *http.Client
}

// NewHTTPDiscoveryClient creates a discovery client using a default timeout when no client is provided.
func NewHTTPDiscoveryClient(client *http.Client) *HTTPDiscoveryClient {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	return &HTTPDiscoveryClient{client: client}
}

// Fetch resolves OIDC discovery metadata from /.well-known/openid-configuration.
// Only issuer and jwks_uri are required by the server bootstrap path.
func (c *HTTPDiscoveryClient) Fetch(ctx context.Context, issuerURL string) (*DiscoveryDocument, error) {
	issuerURL = strings.TrimSpace(strings.TrimRight(issuerURL, "/"))
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerURL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document missing required jwks_uri")
	}

	return &DiscoveryDocument{
		Issuer:  doc.Issuer,
		JWKSURI: doc.JWKSURI,
	}, nil
}
