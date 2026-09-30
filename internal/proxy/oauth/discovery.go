// Package oauth implements OAuth client discovery for the PrivX MCP stdio proxy.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
)

const defaultProtectedResourcePath = "/.well-known/oauth-protected-resource"

// Result is RFC 9728 / RFC 8414 discovery output for one MCP URL.
type Result struct {
	Unauthenticated                   bool
	Resource                          string
	AuthorizationServer               string
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	RegistrationEndpoint              string
	Scopes                            []string
	ScopesSupported                   []string
	TokenAuthMethods                  []string
	CodeChallengeMethods              []string
	GrantTypes                        []string
	ClientIDMetadataDocumentSupported bool
}

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

type asMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	CodeChallengeMethods              []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods                  []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypes                        []string `json:"grant_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
}

// Discover probes mcpURL, follows a 401/403 challenge to protected-resource
// metadata, then loads authorization-server metadata. cfgScopes, when
// non-empty, win over challenge / PRM / AS scopes.
func Discover(ctx context.Context, client *http.Client, mcpURL string, cfgScopes []string, allowHTTP bool) (Result, error) {
	if client == nil {
		return Result{}, fmt.Errorf("http client is required")
	}

	mcp, err := url.Parse(mcpURL)
	if err != nil || mcp.Scheme == "" || mcp.Host == "" {
		return Result{}, fmt.Errorf("mcp_url is not a valid absolute URL")
	}

	if err := httpx.RejectInsecureHTTP(mcp, allowHTTP); err != nil {
		return Result{}, err
	}

	resp, err := probeMCP(ctx, client, mcpURL)
	if err != nil {
		return Result{}, err
	}

	defer func() { _ = resp.Body.Close() }()

	if err := httpx.RejectInsecureHTTP(resp.Request.URL, allowHTTP); err != nil {
		return Result{}, err
	}

	status := resp.StatusCode
	challenge := parseBearerChallenges(resp.Header.Values("WWW-Authenticate"))

	slog.Debug("mcp probe complete",
		"method", resp.Request.Method,
		"status", status,
		"url", resp.Request.URL.String(),
	)

	if status >= 200 && status < 300 {
		return Result{Unauthenticated: true}, nil
	}

	oauthPath := status == http.StatusUnauthorized ||
		(status == http.StatusForbidden && challenge.ResourceMetadata != "")
	if !oauthPath {
		return Result{}, fmt.Errorf("mcp probe returned HTTP %d", status)
	}

	metadataURL, err := protectedResourceURL(mcpURL, challenge.ResourceMetadata)
	if err != nil {
		return Result{}, err
	}

	slog.Debug("fetching protected resource metadata", "url", metadataURL)

	var prm protectedResourceMetadata
	if err := getJSON(ctx, client, metadataURL, &prm); err != nil {
		return Result{}, fmt.Errorf("protected resource metadata: %w", err)
	}

	if strings.TrimSpace(prm.Resource) == "" {
		return Result{}, fmt.Errorf("protected resource metadata is missing resource")
	}

	if len(prm.AuthorizationServers) == 0 {
		return Result{}, fmt.Errorf("protected resource metadata is missing authorization_servers")
	}

	if len(prm.AuthorizationServers) > 1 {
		slog.Warn("protected resource metadata lists multiple authorization servers; using the first",
			"chosen", prm.AuthorizationServers[0],
			"unused", prm.AuthorizationServers[1:],
		)
	}

	issuer := strings.TrimRight(strings.TrimSpace(prm.AuthorizationServers[0]), "/")
	if issuer == "" {
		return Result{}, fmt.Errorf("authorization_servers[0] is empty")
	}

	as, err := fetchASMetadata(ctx, client, issuer)
	if err != nil {
		return Result{}, err
	}

	scopes := resolveScopes(cfgScopes, challenge.Scope, prm.ScopesSupported, as.ScopesSupported)

	return Result{
		Resource:                          prm.Resource,
		AuthorizationServer:               issuer,
		AuthorizationEndpoint:             as.AuthorizationEndpoint,
		TokenEndpoint:                     as.TokenEndpoint,
		RegistrationEndpoint:              as.RegistrationEndpoint,
		Scopes:                            scopes,
		ScopesSupported:                   as.ScopesSupported,
		TokenAuthMethods:                  as.TokenAuthMethods,
		CodeChallengeMethods:              as.CodeChallengeMethods,
		GrantTypes:                        as.GrantTypes,
		ClientIDMetadataDocumentSupported: as.ClientIDMetadataDocumentSupported,
	}, nil
}

func probeMCP(ctx context.Context, client *http.Client, mcpURL string) (*http.Response, error) {
	resp, err := doProbe(ctx, client, http.MethodPost, mcpURL)
	if err != nil {
		return nil, fmt.Errorf("mcp probe POST: %w", err)
	}

	if resp.StatusCode != http.StatusMethodNotAllowed {
		return resp, nil
	}

	_ = resp.Body.Close()

	resp, err = doProbe(ctx, client, http.MethodGet, mcpURL)
	if err != nil {
		return nil, fmt.Errorf("mcp probe GET: %w", err)
	}

	return resp, nil
}

func doProbe(ctx context.Context, client *http.Client, method, mcpURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, mcpURL, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	return client.Do(req)
}

func protectedResourceURL(mcpURL, resourceMetadata string) (string, error) {
	base, err := url.Parse(mcpURL)
	if err != nil {
		return "", fmt.Errorf("mcp_url: %w", err)
	}

	if strings.TrimSpace(resourceMetadata) == "" {
		origin := *base
		origin.Path = defaultProtectedResourcePath
		origin.RawQuery = ""
		origin.Fragment = ""

		return origin.String(), nil
	}

	ref, err := url.Parse(resourceMetadata)
	if err != nil {
		return "", fmt.Errorf("resource_metadata is not a valid URL: %w", err)
	}

	return base.ResolveReference(ref).String(), nil
}

func fetchASMetadata(ctx context.Context, client *http.Client, issuer string) (asMetadata, error) {
	candidates := []string{
		issuer + "/.well-known/openid-configuration",
		issuer + "/.well-known/oauth-authorization-server",
	}

	var errs []error

	for _, raw := range candidates {
		slog.Debug("fetching authorization server metadata", "url", raw)

		var as asMetadata
		if err := getJSON(ctx, client, raw, &as); err != nil {
			errs = append(errs, err)

			continue
		}

		if strings.TrimSpace(as.AuthorizationEndpoint) == "" || strings.TrimSpace(as.TokenEndpoint) == "" {
			errs = append(errs, fmt.Errorf("%s: metadata is missing authorization_endpoint or token_endpoint", raw))

			continue
		}

		if strings.TrimSpace(as.Issuer) == "" {
			as.Issuer = issuer
		}

		return as, nil
	}

	if len(errs) > 0 {
		return asMetadata{}, fmt.Errorf("authorization server metadata: %w", errors.Join(errs...))
	}

	return asMetadata{}, fmt.Errorf("authorization server metadata not found for %s", issuer)
}

func resolveScopes(cfg []string, challengeScope string, prm, as []string) []string {
	if len(cfg) > 0 {
		return append([]string(nil), cfg...)
	}

	if fields := splitScopes(challengeScope); len(fields) > 0 {
		return fields
	}

	if len(prm) > 0 {
		return append([]string(nil), prm...)
	}

	if len(as) > 0 {
		return append([]string(nil), as...)
	}

	return []string{}
}

func splitScopes(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	return strings.FieldsFunc(s, unicode.IsSpace)
}

func getJSON(ctx context.Context, client *http.Client, rawURL string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxJSONBody))

		return fmt.Errorf("%s: unexpected status %d", rawURL, resp.StatusCode)
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody))
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("%s: decode: %w", rawURL, err)
	}

	return nil
}
