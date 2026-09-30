package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreateHostHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
		return response.ResultSet[testconn.RolestoreRole]{
			Items: []testconn.RolestoreRole{{ID: "role-1", Name: "admin"}},
		}, nil
	})
	conn.Handle("POST", "/host-store/api/v1/hosts", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var h hoststore.Host
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatalf("unmarshal host: %v", err)
		}
		if h.CommonName != "web1" {
			t.Errorf("common_name = %q", h.CommonName)
		}
		if len(h.Services) != 1 || h.Services[0].Service != "SSH" {
			t.Errorf("services = %+v", h.Services)
		}
		if len(h.Principals) != 1 || h.Principals[0].Principal != "root" {
			t.Errorf("principals = %+v", h.Principals)
		}
		if len(h.Principals[0].Roles) != 1 || h.Principals[0].Roles[0].ID != "role-1" {
			t.Errorf("principal roles = %+v", h.Principals[0].Roles)
		}
		return response.Identifier{ID: "new-host-id"}, nil
	})

	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"services": []any{
			map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)},
		},
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-host-id" {
		t.Errorf("id = %v, want new-host-id", m["id"])
	}
}

func TestCreateHostHandler_MissingCommonName(t *testing.T) {
	conn := testconn.New(t)
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"addresses": []any{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: common_name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateHostHandler_EmptyAddresses(t *testing.T) {
	conn := testconn.New(t)
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "addresses must contain at least one entry") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateHostHandler_ServicesNotArray(t *testing.T) {
	conn := testconn.New(t)
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"services":    "not-an-array",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "services must be a non-empty array") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateHostHandler_BadServiceItem(t *testing.T) {
	conn := testconn.New(t)
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"services": []any{
			map[string]any{"service": "SSH", "port": float64(22)}, // missing address
		},
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{}},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "services[0]") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateHostHandler_BadPrincipalItem(t *testing.T) {
	conn := testconn.New(t)
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"services": []any{
			map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)},
		},
		"principals": []any{
			map[string]any{"principal": "", "roles": []any{}}, // missing principal
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "principals[0]") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateHostHandler_RoleResolutionFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
		return nil, errors.New("role store unavailable")
	})
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"services": []any{
			map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)},
		},
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to resolve roles") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateHostHandler_CreateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(body any) (any, error) {
		return response.ResultSet[testconn.RolestoreRole]{Items: []testconn.RolestoreRole{{ID: "role-1", Name: "admin"}}}, nil
	})
	conn.Handle("POST", "/host-store/api/v1/hosts", func(body any) (any, error) {
		return nil, errors.New("create failed")
	})
	res, err := createHostHandler(testconn.CtxWithAuth(conn), map[string]any{
		"common_name": "web1",
		"addresses":   []any{"10.0.0.1"},
		"services": []any{
			map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)},
		},
		"principals": []any{
			map[string]any{"principal": "root", "roles": []any{"admin"}},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to create host") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
