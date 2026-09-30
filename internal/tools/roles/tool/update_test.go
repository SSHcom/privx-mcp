package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestUpdateRoleHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{
			ID:            "r1",
			Name:          "old",
			Comment:       "keep-me",
			Permissions:   []string{"roles-view"},
			Tags:          []string{"a"},
			AccessGroupID: "ag1",
			PermitAgent:   false,
		}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var role rolestore.Role
		if err := json.Unmarshal(raw, &role); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if role.Name != "new" {
			t.Errorf("name = %q, want new", role.Name)
		}
		if role.Comment != "updated" {
			t.Errorf("comment = %q, want updated", role.Comment)
		}
		if !role.PermitAgent {
			t.Error("permit_agent = false, want true")
		}
		if len(role.Permissions) != 2 {
			t.Errorf("permissions = %v", role.Permissions)
		}
		if len(role.Tags) != 1 || role.Tags[0] != "b" {
			t.Errorf("tags = %v", role.Tags)
		}
		if role.AccessGroupID != "ag2" {
			t.Errorf("access_group_id = %q", role.AccessGroupID)
		}
		return nil, nil
	})

	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":              "r1",
		"name":            "new",
		"comment":         "updated",
		"permit_agent":    true,
		"permissions":     []any{"roles-view", "roles-manage"},
		"tags":            []any{"b"},
		"access_group_id": "ag2",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "r1" || m["updated"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestUpdateRoleHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_FetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_BadPermissions(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1"}, nil
	})
	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":          "r1",
		"permissions": "not-an-array",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "permissions") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_BadTags(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1"}, nil
	})
	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":   "r1",
		"tags": "not-an-array",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "tags") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_UpdateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1"}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, errors.New("put failed")
	})
	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to update role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_WrongTypePermitAgent(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", PermitAgent: true}, nil
	})
	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":           "r1",
		"permit_agent": 1,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "permit_agent") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
