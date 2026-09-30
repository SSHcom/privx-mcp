package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestRevokeRoleHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 2,
			Items: []rolestore.Role{
				{ID: "r1", Name: "ops"},
				{ID: "r2", Name: "user"},
			},
		}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var roles []rolestore.Role
		if err := json.Unmarshal(raw, &roles); err != nil {
			t.Fatalf("unmarshal roles: %v", err)
		}
		if len(roles) != 1 || roles[0].ID != "r2" {
			t.Errorf("roles after revoke = %+v", roles)
		}
		return nil, nil
	})

	res, err := revokeRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["user_id"] != "u1" || m["role_id"] != "r1" || m["revoked"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestRevokeRoleHandler_NotGranted(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 1,
			Items: []rolestore.Role{{ID: "r2", Name: "user"}},
		}, nil
	})
	res, err := revokeRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "is not granted") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestRevokeRoleHandler_MissingFields(t *testing.T) {
	conn := testconn.New(t)
	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"missing user_id", map[string]any{"role_id": "r1"}, "missing required field: user_id"},
		{"missing role_id", map[string]any{"user_id": "u1"}, "missing required field: role_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := revokeRoleHandler(testconn.CtxWithAuth(conn), tc.params)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !res.IsError || !strings.Contains(res.Content[0].Text, tc.want) {
				t.Errorf("got %q, want containing %q", res.Content[0].Text, tc.want)
			}
		})
	}
}

func TestRevokeRoleHandler_FetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return nil, errors.New("roles failed")
	})
	res, err := revokeRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch user roles") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestRevokeRoleHandler_UpdateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 1,
			Items: []rolestore.Role{{ID: "r1"}},
		}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return nil, errors.New("put failed")
	})
	res, err := revokeRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to revoke role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
