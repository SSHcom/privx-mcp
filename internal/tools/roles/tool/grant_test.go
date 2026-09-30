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

func TestGrantRoleHandler_HappyPermanent(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{Count: 0, Items: nil}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var roles []rolestore.Role
		if err := json.Unmarshal(raw, &roles); err != nil {
			t.Fatalf("unmarshal roles: %v", err)
		}
		if len(roles) != 1 {
			t.Fatalf("roles len = %d", len(roles))
		}
		if roles[0].ID != "r1" || roles[0].GrantType != "PERMANENT" || !roles[0].Explicit {
			t.Errorf("role = %+v", roles[0])
		}
		return nil, nil
	})

	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
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
	if m["user_id"] != "u1" || m["role_id"] != "r1" || m["granted"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestGrantRoleHandler_HappyFloating(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var roles []rolestore.Role
		if err := json.Unmarshal(raw, &roles); err != nil {
			t.Fatalf("unmarshal roles: %v", err)
		}
		if roles[0].GrantType != "FLOATING" || roles[0].FloatingLength != 8 {
			t.Errorf("role = %+v", roles[0])
		}
		return nil, nil
	})

	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":         "u1",
		"role_id":         "r1",
		"grant_type":      "floating",
		"floating_length": 8,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_HappyRestricted(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var roles []rolestore.Role
		if err := json.Unmarshal(raw, &roles); err != nil {
			t.Fatalf("unmarshal roles: %v", err)
		}
		if roles[0].GrantType != "TIME_RESTRICTED" {
			t.Errorf("grant_type = %q", roles[0].GrantType)
		}
		if len(roles[0].GrantValidityPeriods) != 1 {
			t.Fatalf("validity periods = %v", roles[0].GrantValidityPeriods)
		}
		vp := roles[0].GrantValidityPeriods[0]
		if vp.GrantStart != "2025-01-15T09:00:00Z" || vp.GrantEnd != "2025-06-30T17:00:00Z" {
			t.Errorf("validity = %+v", vp)
		}
		return nil, nil
	})

	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":     "u1",
		"role_id":     "r1",
		"grant_type":  "restricted",
		"valid_from":  "2025-01-15T09:00:00Z",
		"valid_until": "2025-06-30T17:00:00Z",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_AlreadyGranted(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 1,
			Items: []rolestore.Role{{ID: "r1", Name: "ops"}},
		}, nil
	})

	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "already granted") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_MissingFields(t *testing.T) {
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
			res, err := grantRoleHandler(testconn.CtxWithAuth(conn), tc.params)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !res.IsError || !strings.Contains(res.Content[0].Text, tc.want) {
				t.Errorf("got %q, want containing %q", res.Content[0].Text, tc.want)
			}
		})
	}
}

func TestGrantRoleHandler_FloatingMissingLength(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":    "u1",
		"role_id":    "r1",
		"grant_type": "floating",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "floating_length") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_RestrictedMissingDates(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":    "u1",
		"role_id":    "r1",
		"grant_type": "restricted",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "valid_from and valid_until") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_InvalidGrantType(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":    "u1",
		"role_id":    "r1",
		"grant_type": "maybe",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "invalid grant_type") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_RoleFetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGrantRoleHandler_UserRolesFetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return nil, errors.New("roles failed")
	})
	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
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

func TestGrantRoleHandler_UpdateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return nil, errors.New("put failed")
	})
	res, err := grantRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id": "u1",
		"role_id": "r1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to grant role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
