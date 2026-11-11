// Package testconn provides a shared fake restapi.Connector for exercising
// MCP tool handlers end-to-end without a live PrivX server.
//
// Tests register routes by HTTP method and URL pattern (with ":name"
// path params) and return JSON-round-trippable response values. The
// connector dispatches SDK calls to the registered handler and
// marshals/unmarshals the response into the SDK's output argument.
//
// This package is only imported from *_test.go files.
package testconn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
)

// FakeConnector is a restapi.Connector that dispatches SDK requests to
// route handlers registered by tests.
type FakeConnector struct {
	t      *testing.T
	mu     sync.Mutex
	routes []route
}

// Handler receives the request body the SDK passed (often a pointer to
// a struct, e.g. *hoststore.Host) and returns a response value that
// gets JSON-round-tripped into the SDK's output argument.
type Handler func(body any) (any, error)

// FetchHandler returns the raw bytes a Fetch() call should yield for a
// matched GET route. Used to exercise handlers that read response bodies
// directly (e.g. downloaded trail logs) instead of JSON-decoding them.
type FetchHandler func() ([]byte, error)

type route struct {
	method   string
	segments []string
	handler  Handler
	fetch    FetchHandler
}

// New creates a FakeConnector that fails the test when an unmatched
// route is dispatched.
func New(t *testing.T) *FakeConnector {
	return &FakeConnector{t: t}
}

// Handle registers a route. method is GET/POST/PUT/DELETE. pattern uses
// ":name" for path params, e.g. "/host-store/api/v1/hosts/:id".
func (c *FakeConnector) Handle(method, pattern string, h Handler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.routes = append(c.routes, route{
		method:   method,
		segments: splitPath(pattern),
		handler:  h,
	})
}

// HandleFetch registers a GET route whose Fetch() returns raw bytes.
// pattern uses ":name" for path params, as with Handle.
func (c *FakeConnector) HandleFetch(pattern string, h FetchHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.routes = append(c.routes, route{
		method:   "GET",
		segments: splitPath(pattern),
		fetch:    h,
	})
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}

	return strings.Split(p, "/")
}

// URL implements restapi.Connector. It formats the pattern with args
// and returns a CURL bound to this connector.
func (c *FakeConnector) URL(pattern string, args ...interface{}) restapi.CURL {
	path := pattern
	if len(args) > 0 {
		path = fmt.Sprintf(pattern, args...)
	}

	return &curl{connector: c, path: path}
}

type curl struct {
	connector *FakeConnector
	path      string
	query     url.Values
}

func (c *curl) Query(v interface{}) restapi.CURL {
	if vals, ok := v.(url.Values); ok {
		c.query = vals
	}

	return c
}
func (c *curl) Header(string, string) restapi.CURL    { return c }
func (c *curl) CookieJar(http.CookieJar) restapi.CURL { return c }
func (c *curl) Status(...int) (http.Header, error)    { return nil, nil }
func (c *curl) Get(out interface{}) (http.Header, error) {
	return c.dispatch("GET", nil, []interface{}{out})
}
func (c *curl) Put(body interface{}, outs ...interface{}) (http.Header, error) {
	return c.dispatch("PUT", body, outs)
}
func (c *curl) Post(body interface{}, outs ...interface{}) (http.Header, error) {
	return c.dispatch("POST", body, outs)
}
func (c *curl) Delete(...interface{}) (http.Header, error) {
	return c.dispatch("DELETE", nil, nil)
}
func (c *curl) Fetch() ([]byte, error) {
	c.connector.mu.Lock()
	routes := c.connector.routes
	c.connector.mu.Unlock()

	incoming := splitPath(c.path)
	for _, r := range routes {
		if r.method != "GET" || r.fetch == nil || !matchPath(r.segments, incoming) {
			continue
		}

		return r.fetch()
	}

	c.connector.t.Fatalf("fake connector: no fetch route for GET %s", c.path)

	return nil, nil
}
func (c *curl) Download(string) error { return nil }

func (c *curl) dispatch(method string, body any, outs []interface{}) (http.Header, error) {
	c.connector.mu.Lock()
	routes := c.connector.routes
	c.connector.mu.Unlock()

	incoming := splitPath(c.path)
	for _, r := range routes {
		if r.method != method || !matchPath(r.segments, incoming) {
			continue
		}

		resp, err := r.handler(body)
		if err != nil {
			return nil, err
		}

		if resp == nil {
			return nil, nil
		}

		raw, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("fake connector: marshal response: %w", err)
		}

		for _, out := range outs {
			if out == nil {
				continue
			}

			if err := json.Unmarshal(raw, out); err != nil {
				return nil, fmt.Errorf("fake connector: unmarshal into %T: %w", out, err)
			}
		}

		return nil, nil
	}

	c.connector.t.Fatalf("fake connector: no route for %s %s", method, c.path)

	return nil, nil
}

func matchPath(segs, incoming []string) bool {
	if len(segs) != len(incoming) {
		return false
	}

	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") {
			continue
		}

		if seg != incoming[i] {
			return false
		}
	}

	return true
}

// CtxWithAuth returns a context carrying an AuthContext whose
// Connector is c and Username is "tester".
func CtxWithAuth(c *FakeConnector) context.Context {
	return CtxWithAuthRoles(c, nil)
}

// CtxWithAuthRoles is like CtxWithAuth but also sets Roles.
func CtxWithAuthRoles(c *FakeConnector, roles []auth.Role) context.Context {
	return auth.NewContext(context.Background(), &auth.AuthContext{
		Username:  "tester",
		Roles:     roles,
		Connector: c,
	})
}

// CtxNoAuth returns a context with no AuthContext set.
func CtxNoAuth() context.Context {
	return context.Background()
}

// DecodeResult unmarshals a tool result's text content into a map.
func DecodeResult(t *testing.T, text string) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("decode result %q: %v", text, err)
	}

	return m
}

// DecodeResultAny decodes a tool result text into a generic any value,
// supporting both JSON objects and arrays.
func DecodeResultAny(t *testing.T, text string) any {
	t.Helper()

	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("decode result %q: %v", text, err)
	}

	return v
}

// RolestoreRole mirrors the rolestore.Role fields used by ResolveRoles.
// The SDK only round-trips id and name through JSON.
type RolestoreRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
