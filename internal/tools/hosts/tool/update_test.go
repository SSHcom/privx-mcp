package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestUpdateHostHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{
			ID:           "h1",
			CommonName:   "old-name",
			Addresses:    []string{"10.0.0.1"},
			Organization: "old-org",
		}, nil
	})
	conn.Handle("PUT", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var h hoststore.Host
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if h.CommonName != "new-name" {
			t.Errorf("common_name = %q, want new-name", h.CommonName)
		}
		if h.Organization != "old-org" {
			t.Errorf("organization = %q, want preserved old-org", h.Organization)
		}
		if len(h.Addresses) != 2 || h.Addresses[0] != "10.0.0.2" {
			t.Errorf("addresses = %v, want wholesale-replaced", h.Addresses)
		}
		return nil, nil
	})

	res, err := updateHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":          "h1",
		"common_name": "new-name",
		"addresses":   []any{"10.0.0.2", "10.0.0.3"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "h1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["updated"] != true {
		t.Errorf("updated = %v, want true", m["updated"])
	}
}

func TestUpdateHostHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := updateHostHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateHostHandler_FetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := updateHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch host") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateHostHandler_BadBoolField(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1"}, nil
	})
	res, err := updateHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":            "h1",
		"audit_enabled": "not-a-bool",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "audit_enabled") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateHostHandler_UpdateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1"}, nil
	})
	conn.Handle("PUT", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, errors.New("put failed")
	})
	res, err := updateHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to update host") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
