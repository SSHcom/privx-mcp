package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/store"
)

// ErrInvalidGrant is a token-endpoint invalid_grant response.
var ErrInvalidGrant = errors.New("invalid_grant")

type clientAuth struct {
	ClientID                string
	ClientSecret            string
	TokenEndpointAuthMethod string
}

type tokenJSON struct {
	AccessToken      string      `json:"access_token"`
	TokenType        string      `json:"token_type"`
	RefreshToken     string      `json:"refresh_token"`
	ExpiresIn        flexibleInt `json:"expires_in"`
	Error            string      `json:"error"`
	ErrorDescription string      `json:"error_description"`
}

// flexibleInt accepts expires_in as either a JSON number or a JSON string.
// The Azure AD v1 token endpoint (sts.windows.net issuer) returns expires_in
// as a quoted string, unlike the OAuth spec and the v2 endpoint, which return
// a number.
type flexibleInt int

func (f *flexibleInt) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		*f = 0

		return nil
	}

	// Strip surrounding quotes when the value is a JSON string.
	if data[0] == '"' {
		unquoted, err := strconv.Unquote(string(data))
		if err != nil {
			return fmt.Errorf("expires_in: %w", err)
		}

		data = []byte(unquoted)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		*f = 0

		return nil
	}

	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("expires_in: %w", err)
	}

	*f = flexibleInt(n)

	return nil
}

func exchangeCode(
	ctx context.Context,
	httpClient *http.Client,
	p exchangeParams,
) (store.Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", p.Code)
	form.Set("redirect_uri", p.RedirectURI)
	form.Set("code_verifier", p.Verifier)
	setResource(form, p.Resource)

	return tokenRequest(ctx, httpClient, p.TokenURL, p.Auth, form, time.Now())
}

type exchangeParams struct {
	TokenURL    string
	Auth        clientAuth
	RedirectURI string
	Code        string
	Verifier    string
	Resource    string
}

func refreshTokens(
	ctx context.Context,
	httpClient *http.Client,
	tokenURL string,
	auth clientAuth,
	refreshToken, resource string,
) (store.Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	setResource(form, resource)

	tok, err := tokenRequest(ctx, httpClient, tokenURL, auth, form, time.Now())
	if err != nil {
		return store.Tokens{}, err
	}

	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}

	return tok, nil
}

func setResource(form url.Values, resource string) {
	if resource != "" {
		form.Set("resource", resource)
	}
}

func tokenRequest(
	ctx context.Context,
	httpClient *http.Client,
	tokenURL string,
	auth clientAuth,
	form url.Values,
	now time.Time,
) (store.Tokens, error) {
	if httpClient == nil {
		return store.Tokens{}, fmt.Errorf("http client is required")
	}

	form = cloneValues(form)
	grant := form.Get("grant_type")

	switch auth.TokenEndpointAuthMethod {
	case "client_secret_post":
		form.Set("client_id", auth.ClientID)
		form.Set("client_secret", auth.ClientSecret)
	case "client_secret_basic":
		form.Set("client_id", auth.ClientID)
	default:
		return store.Tokens{}, fmt.Errorf("unsupported token_endpoint_auth_method %q", auth.TokenEndpointAuthMethod)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return store.Tokens{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if auth.TokenEndpointAuthMethod == "client_secret_basic" {
		req.SetBasicAuth(auth.ClientID, auth.ClientSecret)
	}

	slog.Info("oauth token request", "url", tokenURL, "grant_type", grant)

	resp, err := httpClient.Do(req)
	if err != nil {
		return store.Tokens{}, fmt.Errorf("token request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	slog.Info("oauth token response", "url", tokenURL, "grant_type", grant, "status", resp.StatusCode)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBody))
	if err != nil {
		return store.Tokens{}, fmt.Errorf("token response: %w", err)
	}

	var parsed tokenJSON
	if len(body) > 0 {
		if err := json.Unmarshal(body, &parsed); err != nil {
			return store.Tokens{}, fmt.Errorf("token response decode: %w", err)
		}
	}

	if parsed.Error == "invalid_grant" {
		return store.Tokens{}, fmt.Errorf("%w", ErrInvalidGrant)
	}

	if resp.StatusCode != http.StatusOK {
		if parsed.Error != "" {
			return store.Tokens{}, fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, parsed.Error)
		}

		return store.Tokens{}, fmt.Errorf("token endpoint HTTP %d", resp.StatusCode)
	}

	if strings.TrimSpace(parsed.AccessToken) == "" {
		return store.Tokens{}, fmt.Errorf("token endpoint omitted access_token")
	}

	tokenType := parsed.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	expiresAt := now.UTC()
	if parsed.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(int(parsed.ExpiresIn)) * time.Second).UTC()
	}

	return store.Tokens{
		AccessToken:  parsed.AccessToken,
		TokenType:    tokenType,
		RefreshToken: parsed.RefreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, vs := range in {
		out[k] = append([]string(nil), vs...)
	}

	return out
}
