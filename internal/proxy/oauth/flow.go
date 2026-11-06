package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/store"
)

// ObtainParams is the input to Obtain.
type ObtainParams struct {
	HTTP         *http.Client
	Config       *config.Config
	Discovered   Result
	AuthDir      string
	OpenBrowser  func(string) error
	Now          func() time.Time
	ResetSession bool
}

// Obtain loads, refreshes, or interactively fetches tokens for a static confidential client.
func Obtain(ctx context.Context, p ObtainParams) (store.Tokens, error) {
	if p.Config == nil {
		return store.Tokens{}, fmt.Errorf("config is required")
	}

	if err := requireConfidentialClient(p.Config.Client); err != nil {
		return store.Tokens{}, err
	}

	if err := requireS256(p.Discovered.CodeChallengeMethods); err != nil {
		return store.Tokens{}, err
	}

	dir := p.AuthDir
	if dir == "" {
		var err error

		dir, err = store.Dir()
		if err != nil {
			return store.Tokens{}, err
		}
	}

	now := time.Now
	if p.Now != nil {
		now = p.Now
	}

	key := store.Key(p.Config.MCPURL, p.Discovered.Resource, p.Config.Client.ClientID)

	auth := clientAuth{
		ClientID:                p.Config.Client.ClientID,
		ClientSecret:            p.Config.Client.ClientSecret,
		TokenEndpointAuthMethod: p.Config.Client.TokenEndpointAuthMethod,
	}

	if p.ResetSession {
		slog.Info("reset session: ignoring stored oauth tokens")

		return interactive(ctx, p, dir, key, auth)
	}

	tok, err := store.Load(dir, key)
	if err == nil && tok.Usable(now()) {
		slog.Info("using stored oauth tokens", "expires_at", tok.ExpiresAt.Format(time.RFC3339))

		return tok, nil
	}

	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.Tokens{}, err
	}

	if err == nil && tok.RefreshToken != "" {
		refreshed, reused, rerr := refreshStored(ctx, refreshStoredParams{
			HTTP:     p.HTTP,
			TokenURL: p.Discovered.TokenEndpoint,
			Auth:     auth,
			Resource: p.Discovered.Resource,
			Dir:      dir,
			Key:      key,
			Now:      now,
		})
		if rerr == nil {
			if reused {
				slog.Info("using stored oauth tokens", "expires_at", refreshed.ExpiresAt.Format(time.RFC3339))
			} else {
				slog.Info("oauth token refresh complete", "expires_at", refreshed.ExpiresAt.Format(time.RFC3339))
			}

			return refreshed, nil
		}

		slog.Warn("oauth token refresh failed; starting browser flow", "err", rerr)
	}

	return interactive(ctx, p, dir, key, auth)
}

type refreshStoredParams struct {
	HTTP     *http.Client
	TokenURL string
	Auth     clientAuth
	Resource string
	Dir      string
	Key      string
	Now      func() time.Time
}

// refreshStored reloads the token file under the shared lock, refreshes when
// it is still stale, and deletes it only when the rejected refresh token is
// still the one stored.
func refreshStored(ctx context.Context, p refreshStoredParams) (store.Tokens, bool, error) {
	var (
		out    store.Tokens
		reused bool
	)

	err := store.WithLock(p.Dir, p.Key, func() error {
		tok, err := store.Load(p.Dir, p.Key)
		if err != nil {
			return err
		}

		if tok.Usable(p.Now()) {
			out = tok
			reused = true

			return nil
		}

		if tok.RefreshToken == "" {
			return fmt.Errorf("stored oauth tokens have no refresh token")
		}

		refreshed, rerr := refreshTokens(
			ctx,
			p.HTTP,
			p.TokenURL,
			p.Auth,
			tok.RefreshToken,
			p.Resource,
		)
		if rerr != nil {
			if errors.Is(rerr, ErrInvalidGrant) {
				if delErr := store.DeleteIfRefreshToken(p.Dir, p.Key, tok.RefreshToken); delErr != nil {
					slog.Warn("failed to delete invalid stored tokens", "err", delErr)
				}
			}

			return rerr
		}

		if err := store.Save(p.Dir, p.Key, refreshed); err != nil {
			return err
		}

		out = refreshed

		return nil
	})

	return out, reused, err
}

func interactive(
	ctx context.Context,
	p ObtainParams,
	dir, key string,
	auth clientAuth,
) (store.Tokens, error) {
	cb := p.Config.Callback
	redirectURI := RedirectURI(cb)

	pair, err := generatePKCE()
	if err != nil {
		return store.Tokens{}, err
	}

	state, err := generateState()
	if err != nil {
		return store.Tokens{}, err
	}

	prompt := ""
	if p.ResetSession {
		prompt = "login"
	}

	authURL, err := authorizeURL(authorizeParams{
		AuthorizationEndpoint: p.Discovered.AuthorizationEndpoint,
		ClientID:              auth.ClientID,
		RedirectURI:           redirectURI,
		Scopes:                p.Discovered.Scopes,
		State:                 state,
		Challenge:             pair.Challenge,
		Resource:              p.Discovered.Resource,
		Prompt:                prompt,
	})
	if err != nil {
		return store.Tokens{}, err
	}

	listener, err := StartCallback(cb, state)
	if err != nil {
		return store.Tokens{}, err
	}

	defer func() { _ = listener.Close() }()

	open := p.OpenBrowser
	if open == nil {
		open = openBrowser
	}

	if err := open(authURL); err != nil {
		slog.Info("could not open browser; open this URL to authenticate", "url", authURL, "err", err)
	} else {
		slog.Info("waiting for oauth callback", "redirect_uri", redirectURI)
		slog.Debug("authorization url", "url", authURL)
	}

	timeout := time.Duration(cb.AuthTimeoutSeconds) * time.Second

	code, err := listener.Wait(ctx, timeout)
	if err != nil {
		return store.Tokens{}, err
	}

	tok, err := exchangeCode(ctx, p.HTTP, exchangeParams{
		TokenURL:    p.Discovered.TokenEndpoint,
		Auth:        auth,
		RedirectURI: redirectURI,
		Code:        code,
		Verifier:    pair.Verifier,
		Resource:    p.Discovered.Resource,
	})
	if err != nil {
		return store.Tokens{}, err
	}

	if p.ResetSession {
		return tok, nil
	}

	if err := store.WithLock(dir, key, func() error {
		return store.Save(dir, key, tok)
	}); err != nil {
		return store.Tokens{}, err
	}

	return tok, nil
}

type authorizeParams struct {
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	Scopes                []string
	State                 string
	Challenge             string
	Resource              string
	Prompt                string
}

func authorizeURL(p authorizeParams) (string, error) {
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("authorization_endpoint is not a valid absolute URL: %w", err)
	}

	if !httpx.AbsoluteHTTP(u) {
		return "", fmt.Errorf("authorization_endpoint must be an absolute http or https URL")
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("state", p.State)
	q.Set("code_challenge", p.Challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "offline")

	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, " "))
	}

	if p.Resource != "" {
		q.Set("resource", p.Resource)
	}

	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func requireConfidentialClient(c config.ClientConfig) error {
	id := strings.TrimSpace(c.ClientID)
	if id == "" {
		return fmt.Errorf("confidential client required for this MCP URL: set client.client_id and client.client_secret")
	}

	if c.ClientSecret == "" {
		return fmt.Errorf("public clients and DCR are not implemented yet: set client.client_secret")
	}

	switch c.TokenEndpointAuthMethod {
	case "client_secret_post", "client_secret_basic":
		return nil
	default:
		return fmt.Errorf("client.token_endpoint_auth_method must be client_secret_post or client_secret_basic")
	}
}

func requireS256(methods []string) error {
	if len(methods) == 0 {
		return nil
	}

	for _, m := range methods {
		if strings.EqualFold(strings.TrimSpace(m), "S256") {
			return nil
		}
	}

	return fmt.Errorf("authorization server does not support PKCE S256")
}
