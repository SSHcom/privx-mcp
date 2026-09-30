// Package httpx provides the shared HTTP client for the PrivX MCP proxy.
package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const requestTimeout = 10 * time.Second

// NewClient returns a client with a per-request timeout, no cookie jar, and
// optional rejection of non-loopback http redirects.
func NewClient(allowHTTP bool) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := RejectInsecureHTTP(req.URL, allowHTTP); err != nil {
				return err
			}

			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}

			return nil
		},
	}
}

// WithoutTimeout returns a shallow copy of base with no overall request
// Timeout. Use it for MCP traffic whose lifetime is governed by context.
func WithoutTimeout(base *http.Client) *http.Client {
	if base == nil {
		base = NewClient(false)
	}

	cloned := *base
	cloned.Timeout = 0

	return &cloned
}

// TokenSource yields an access token for the current request.
type TokenSource interface {
	AccessToken() string
}

type staticToken string

func (s staticToken) AccessToken() string {
	return string(s)
}

// WithBearer returns a shallow copy of base that sets Authorization: Bearer
// from a frozen accessToken. Prefer WithBearerSource when the token can change.
func WithBearer(base *http.Client, accessToken string) *http.Client {
	return WithBearerSource(base, staticToken(strings.TrimSpace(accessToken)))
}

// WithBearerSource returns a shallow copy of base that reads the access token
// on each request. An empty token omits Authorization. The original client is
// unchanged.
func WithBearerSource(base *http.Client, source TokenSource) *http.Client {
	if base == nil {
		base = NewClient(false)
	}

	cloned := *base

	inner := base.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}

	cloned.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		token := ""
		if source != nil {
			token = strings.TrimSpace(source.AccessToken())
		}

		if token != "" {
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", "Bearer "+token)
		}

		return inner.RoundTrip(req)
	})

	return &cloned
}

// RejectInsecureHTTP errors when u is non-loopback http and allowHTTP is false.
func RejectInsecureHTTP(u *url.URL, allowHTTP bool) error {
	if u == nil || u.Scheme != "http" {
		return nil
	}

	if allowHTTP || isLoopbackHost(u.Hostname()) {
		return nil
	}

	return fmt.Errorf("refusing http URL %q (allow_http is false)", u.String())
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback()
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
