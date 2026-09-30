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

func TestCreateRoleHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var role rolestore.Role
		if err := json.Unmarshal(raw, &role); err != nil {
			t.Fatalf("unmarshal role: %v", err)
		}
		if role.Name != "ops" {
			t.Errorf("name = %q, want ops", role.Name)
		}
		if role.Comment != "operators" {
			t.Errorf("comment = %q", role.Comment)
		}
		if len(role.Permissions) != 1 || role.Permissions[0] != "roles-view" {
			t.Errorf("permissions = %v", role.Permissions)
		}
		if len(role.Tags) != 1 || role.Tags[0] != "team" {
			t.Errorf("tags = %v", role.Tags)
		}
		if role.AccessGroupID != "ag1" {
			t.Errorf("access_group_id = %q", role.AccessGroupID)
		}
		return response.Identifier{ID: "new-role-id"}, nil
	})

	res, err := createRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":            "ops",
		"comment":         "operators",
		"permissions":     []any{"roles-view"},
		"tags":            []any{"team"},
		"access_group_id": "ag1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-role-id" {
		t.Errorf("id = %v, want new-role-id", m["id"])
	}
}

func TestCreateRoleHandler_MissingName(t *testing.T) {
	conn := testconn.New(t)
	res, err := createRoleHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRoleHandler_BadPermissions(t *testing.T) {
	conn := testconn.New(t)
	res, err := createRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":        "ops",
		"permissions": "not-an-array",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "permissions") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRoleHandler_BadTags(t *testing.T) {
	conn := testconn.New(t)
	res, err := createRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name": "ops",
		"tags": "not-an-array",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "tags") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateRoleHandler_CreateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/roles", func(body any) (any, error) {
		return nil, errors.New("create failed")
	})
	res, err := createRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"name": "ops"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to create role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
