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

func TestUpdateRoleHandler_ContextKeepsOmittedFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{
			ID: "r1",
			Context: rolestore.ContextualLimit{
				Enabled:   true,
				BlockRole: true,
				Validity:  []string{"MON", "TUE"},
				StartTime: "09:00",
				EndTime:   "17:00",
				TimeZone:  "Europe/Helsinki",
				IPMasks:   []string{"10.0.0.0/8"},
			},
		}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var role rolestore.Role
		if err := json.Unmarshal(raw, &role); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := role.Context
		if !got.Enabled || !got.BlockRole {
			t.Errorf("flags = enabled %v block %v", got.Enabled, got.BlockRole)
		}
		if got.StartTime != "08:00" || got.EndTime != "17:00" {
			t.Errorf("window = %s-%s", got.StartTime, got.EndTime)
		}
		if got.TimeZone != "Europe/Helsinki" {
			t.Errorf("timezone = %q", got.TimeZone)
		}
		if len(got.Validity) != 2 || got.Validity[0] != "MON" || got.Validity[1] != "TUE" {
			t.Errorf("validity = %v", got.Validity)
		}
		if len(got.IPMasks) != 1 || got.IPMasks[0] != "10.0.0.0/8" {
			t.Errorf("ip_masks = %v", got.IPMasks)
		}
		return nil, nil
	})

	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id": "r1",
		"context": map[string]any{
			"start_time": "08:00",
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_ContextReplacesSuppliedList(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{
			ID: "r1",
			Context: rolestore.ContextualLimit{
				Enabled:  true,
				TimeZone: "UTC",
				IPMasks:  []string{"10.0.0.0/8"},
			},
		}, nil
	})
	conn.Handle("PUT", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var role rolestore.Role
		if err := json.Unmarshal(raw, &role); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if role.Context.TimeZone != "UTC" || !role.Context.Enabled {
			t.Errorf("untouched context = %+v", role.Context)
		}
		if len(role.Context.IPMasks) != 1 || role.Context.IPMasks[0] != "192.168.1.0/24" {
			t.Errorf("ip_masks = %v", role.Context.IPMasks)
		}
		return nil, nil
	})

	res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id": "r1",
		"context": map[string]any{
			"ip_masks": []any{"192.168.1.0/24"},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestUpdateRoleHandler_ContextWrongType(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{
			ID: "r1",
			Context: rolestore.ContextualLimit{
				Enabled: true,
				IPMasks: []string{"10.0.0.0/8"},
			},
		}, nil
	})

	cases := []struct {
		name    string
		context any
		want    string
	}{
		{name: "not an object", context: "10.0.0.0/8", want: "context must be an object"},
		{name: "bad ip_masks", context: map[string]any{"ip_masks": "10.0.0.0/8"}, want: "context.ip_masks"},
		{name: "bad validity", context: map[string]any{"validity": 1}, want: "context.validity"},
		{name: "bad timezone", context: map[string]any{"timezone": 5}, want: "context.timezone"},
		{name: "bad enabled", context: map[string]any{"enabled": "yes"}, want: "context.enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := updateRoleHandler(testconn.CtxWithAuth(conn), map[string]any{
				"id":      "r1",
				"context": tc.context,
			})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !res.IsError || !strings.Contains(res.Content[0].Text, tc.want) {
				t.Errorf("got %q, want %q", res.Content[0].Text, tc.want)
			}
		})
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
