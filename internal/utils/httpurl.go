package utils

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const httpClientTimeout = 10 * time.Second

// NewHTTPClient returns a client that accepts only absolute http and https URLs.
// Plain HTTP to a non-loopback host is rejected unless allowHTTP is set.
// A redirect is followed only when its host matches the first request, and the
// redirect target is checked the same way.
func NewHTTPClient(allowHTTP bool) *http.Client {
	return &http.Client{
		Timeout:   httpClientTimeout,
		Transport: httpSchemeTransport{allowHTTP: allowHTTP, next: http.DefaultTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if err := rejectHTTPRequest(req, allowHTTP); err != nil {
				return err
			}

			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}

			origin := via[0].URL
			if !SameRedirectHost(origin, req.URL) {
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

// RequireHTTPURL parses raw as an absolute http or https URL.
// Non-loopback http is rejected unless allowHTTP is set.
func RequireHTTPURL(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !absoluteHTTP(u) {
		return nil, fmt.Errorf("URL %q is not an absolute http or https URL", raw)
	}

	if err := rejectInsecureHTTP(u, allowHTTP); err != nil {
		return nil, err
	}

	return u, nil
}

// SameRedirectHost reports whether from and to name the same host and port.
// Default ports 80 and 443 are treated as unset.
func SameRedirectHost(from, to *url.URL) bool {
	if from == nil || to == nil {
		return false
	}

	return strings.EqualFold(from.Hostname(), to.Hostname()) && redirectPort(from) == redirectPort(to)
}

func absoluteHTTP(u *url.URL) bool {
	if u == nil || u.Host == "" || u.Opaque != "" {
		return false
	}

	return u.Scheme == "http" || u.Scheme == "https"
}

func rejectInsecureHTTP(u *url.URL, allowHTTP bool) error {
	if u == nil || u.Scheme != "http" {
		return nil
	}

	if allowHTTP || isLoopbackHost(u.Hostname()) {
		return nil
	}

	return fmt.Errorf("refusing http URL %q (allow_http is false)", u.String())
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

type httpSchemeTransport struct {
	allowHTTP bool
	next      http.RoundTripper
}

func (t httpSchemeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rejectHTTPRequest(req, t.allowHTTP); err != nil {
		return nil, err
	}

	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}

	return next.RoundTrip(req)
}

func rejectHTTPRequest(req *http.Request, allowHTTP bool) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("request URL is required")
	}

	_, err := RequireHTTPURL(req.URL.String(), allowHTTP)

	return err
}
