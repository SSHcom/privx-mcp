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
// rejection of non-loopback http URLs unless allowHTTP is set. A redirect is
// followed only when its host matches the first request. The checks cover the
// initial request and redirects, so metadata and token requests cannot leave
// over plain HTTP when allowHTTP is false, and cannot be sent to another host.
func NewClient(allowHTTP bool) *http.Client {
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: schemeTransport{allowHTTP: allowHTTP, next: http.DefaultTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := rejectRequestURL(req, allowHTTP); err != nil {
				return err
			}

			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}

			origin := via[0].URL
			if !sameRedirectHost(origin, req.URL) {
				from := ""
				if origin != nil {
					from = origin.Host
				}

				return fmt.Errorf("refusing redirect from %q to %q", from, req.URL.Host)
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

// RequireHTTPURL parses raw as an absolute http or https URL.
// Non-loopback http is rejected unless allowHTTP is set.
func RequireHTTPURL(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !AbsoluteHTTP(u) {
		return nil, fmt.Errorf("URL %q is not an absolute http or https URL", raw)
	}

	if err := RejectInsecureHTTP(u, allowHTTP); err != nil {
		return nil, err
	}

	return u, nil
}

// AbsoluteHTTP reports whether u is an absolute http or https URL.
func AbsoluteHTTP(u *url.URL) bool {
	if u == nil || u.Host == "" || u.Opaque != "" {
		return false
	}

	return u.Scheme == "http" || u.Scheme == "https"
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

func sameRedirectHost(from, to *url.URL) bool {
	if from == nil || to == nil {
		return false
	}

	return strings.EqualFold(from.Hostname(), to.Hostname()) && redirectPort(from) == redirectPort(to)
}

func redirectPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		return ""
	}

	defaultHTTPS := u.Scheme == "https" && port == "443"

	defaultHTTP := u.Scheme == "http" && port == "80"
	if defaultHTTPS || defaultHTTP {
		return ""
	}

	return port
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

type schemeTransport struct {
	allowHTTP bool
	next      http.RoundTripper
}

func (t schemeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rejectRequestURL(req, t.allowHTTP); err != nil {
		return nil, err
	}

	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}

	return next.RoundTrip(req)
}

func rejectRequestURL(req *http.Request, allowHTTP bool) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("request URL is required")
	}

	_, err := RequireHTTPURL(req.URL.String(), allowHTTP)

	return err
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
