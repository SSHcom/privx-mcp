package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/httpx"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/store"
)

// refreshTimeout bounds a token refresh after it is detached from the caller.
// Detach keeps one cancelled MCP request from aborting a token rotation that
// other requests are waiting on.
const refreshTimeout = 15 * time.Second

// Session holds in-memory OAuth tokens and refreshes them for MCP traffic.
type Session struct {
	mu sync.Mutex

	http      *http.Client
	dir       string
	key       string
	tokenURL  string
	auth      clientAuth
	resource  string
	now       func() time.Time
	tokens    store.Tokens
	dead      bool
	ephemeral bool

	inflight *refreshWait
	// onRefreshWait, when set, runs after this call joins an in-flight refresh.
	// Tests use it to observe that join. Production leaves it nil.
	onRefreshWait func()
}

type refreshWait struct {
	done chan struct{}
	err  error
}

// SessionParams is the input to NewSession.
type SessionParams struct {
	HTTP       *http.Client
	Config     *config.Config
	Discovered Result
	Tokens     store.Tokens
	AuthDir    string
	Now        func() time.Time
	Ephemeral  bool
}

// NewSession wraps tokens obtained at startup for in-process refresh.
func NewSession(p SessionParams) (*Session, error) {
	if p.HTTP == nil {
		return nil, fmt.Errorf("http client is required")
	}

	if p.Config == nil {
		return nil, fmt.Errorf("config is required")
	}

	dir := p.AuthDir
	if dir == "" {
		var err error

		dir, err = store.Dir()
		if err != nil {
			return nil, err
		}
	}

	now := p.Now
	if now == nil {
		now = time.Now
	}

	return &Session{
		http:     p.HTTP,
		dir:      dir,
		key:      store.Key(p.Config.MCPURL, p.Discovered.Resource, p.Config.Client.ClientID),
		tokenURL: p.Discovered.TokenEndpoint,
		auth: clientAuth{
			ClientID:                p.Config.Client.ClientID,
			ClientSecret:            p.Config.Client.ClientSecret,
			TokenEndpointAuthMethod: p.Config.Client.TokenEndpointAuthMethod,
		},
		resource:  p.Discovered.Resource,
		now:       now,
		tokens:    p.Tokens,
		ephemeral: p.Ephemeral,
	}, nil
}

// AccessToken returns the current MCP access token.
func (s *Session) AccessToken() string {
	if s == nil {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.tokens.AccessToken
}

// MCPHTTP returns the streamable HTTP client. When sess is nil, requests have
// no Authorization header and 401s are not retried as a refresh.
func MCPHTTP(base *http.Client, sess *Session) *http.Client {
	mcp := httpx.WithoutTimeout(base)
	if sess == nil {
		return mcp
	}

	withBearer := httpx.WithBearerSource(mcp, sess)
	cloned := *withBearer

	inner := withBearer.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}

	cloned.Transport = &refreshTransport{inner: inner, sess: sess}

	return &cloned
}

type refreshTransport struct {
	inner http.RoundTripper
	sess  *Session
}

func (t *refreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	refreshed, err := t.sess.ensure(req.Context())
	if err != nil {
		return nil, err
	}

	prepared, err := snapshotRequest(req)
	if err != nil {
		return nil, err
	}

	sent := t.sess.AccessToken()

	resp, err := t.inner.RoundTrip(prepared)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized || refreshed {
		return resp, nil
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()

	if err := t.sess.doRefresh(req.Context(), false, sent); err != nil {
		return nil, err
	}

	retry, err := cloneForRetry(prepared)
	if err != nil {
		return nil, err
	}

	return t.inner.RoundTrip(retry)
}

func (s *Session) ensure(ctx context.Context) (bool, error) {
	s.mu.Lock()
	dead := s.dead
	usable := s.tokens.Usable(s.now())
	rt := s.tokens.RefreshToken
	s.mu.Unlock()

	if dead {
		return false, fmt.Errorf("%w: restart the MCP server to log in again", ErrInvalidGrant)
	}

	if usable {
		return false, nil
	}

	if rt == "" {
		return false, fmt.Errorf("access token expired; restart the MCP server to log in again")
	}

	if err := s.doRefresh(ctx, true, ""); err != nil {
		return false, err
	}

	return true, nil
}

func (s *Session) doRefresh(ctx context.Context, onlyIfStale bool, sentAccess string) error {
	s.mu.Lock()

	if s.dead {
		s.mu.Unlock()

		return fmt.Errorf("%w: restart the MCP server to log in again", ErrInvalidGrant)
	}

	if s.inflight != nil {
		wait := s.inflight
		joined := s.onRefreshWait
		s.mu.Unlock()

		if joined != nil {
			joined()
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.done:
			return wait.err
		}
	}

	if onlyIfStale && s.tokens.Usable(s.now()) {
		s.mu.Unlock()

		return nil
	}

	if sentAccess != "" && s.tokens.AccessToken != sentAccess {
		s.mu.Unlock()

		return nil
	}

	if s.tokens.RefreshToken == "" {
		s.mu.Unlock()

		return fmt.Errorf("no refresh token; restart the MCP server to log in again")
	}

	wait := &refreshWait{done: make(chan struct{})}
	s.inflight = wait
	rt := s.tokens.RefreshToken
	s.mu.Unlock()

	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()

	tok, refreshed, err := s.refreshShared(refreshCtx, rt, sentAccess)

	s.mu.Lock()
	s.inflight = nil

	if err != nil {
		if errors.Is(err, ErrInvalidGrant) {
			s.tokens = store.Tokens{}
			s.dead = true
		}

		wait.err = s.invalidateOnGrant(err)
		s.mu.Unlock()
		close(wait.done)

		return wait.err
	}

	s.tokens = tok
	s.mu.Unlock()
	close(wait.done)

	if refreshed {
		slog.Info("oauth token refresh complete", "expires_at", tok.ExpiresAt.Format(time.RFC3339))
	} else {
		slog.Info("using stored oauth tokens", "expires_at", tok.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

// refreshShared refreshes rt. A shared token file is locked for the request
// and the save or delete. A usable file written by another proxy is adopted.
// sentAccess is the bearer that received 401; an unchanged stored access token
// is refreshed instead of adopted.
func (s *Session) refreshShared(ctx context.Context, rt, sentAccess string) (store.Tokens, bool, error) {
	if s.ephemeral {
		tok, err := refreshTokens(
			ctx,
			s.http,
			s.tokenURL,
			s.auth,
			rt,
			s.resource,
		)

		return tok, err == nil, err
	}

	var (
		out       store.Tokens
		refreshed bool
	)

	err := store.WithLock(s.dir, s.key, func() error {
		disk, loadErr := store.Load(s.dir, s.key)
		if loadErr != nil && !errors.Is(loadErr, store.ErrNotFound) {
			return loadErr
		}

		diskUsable := loadErr == nil && disk.Usable(s.now())
		rejectedCurrent := sentAccess != "" && disk.AccessToken == sentAccess

		if diskUsable && !rejectedCurrent {
			out = disk

			return nil
		}

		useRT := rt
		if loadErr == nil && disk.RefreshToken != "" {
			useRT = disk.RefreshToken
		}

		tok, err := refreshTokens(
			ctx,
			s.http,
			s.tokenURL,
			s.auth,
			useRT,
			s.resource,
		)
		if err != nil {
			if errors.Is(err, ErrInvalidGrant) {
				if delErr := store.DeleteIfRefreshToken(s.dir, s.key, useRT); delErr != nil {
					slog.Warn("failed to delete invalid stored tokens", "err", delErr)
				}
			}

			return err
		}

		if err := store.Save(s.dir, s.key, tok); err != nil {
			return err
		}

		out = tok
		refreshed = true

		return nil
	})

	return out, refreshed, err
}

func (s *Session) invalidateOnGrant(err error) error {
	if !errors.Is(err, ErrInvalidGrant) {
		return err
	}

	slog.Error("oauth refresh token rejected; restart the MCP server to log in again")

	return fmt.Errorf("%w: restart the MCP server to log in again", ErrInvalidGrant)
}

func snapshotRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())

	if req.Body == nil || req.Body == http.NoBody {
		return clone, nil
	}

	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}

		clone.Body = body
		clone.GetBody = req.GetBody

		return clone, nil
	}

	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()

	if err != nil {
		return nil, err
	}

	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	clone.ContentLength = int64(len(body))

	return clone, nil
}

func cloneForRetry(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())

	if req.GetBody == nil {
		return clone, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}

	clone.Body = body
	clone.GetBody = req.GetBody

	return clone, nil
}
