package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func sampleRole() rolestore.Role {
	return rolestore.Role{
		ID:   "r1",
		Name: "admin",
		Context: rolestore.ContextualLimit{
			Enabled:   true,
			TimeZone:  "UTC",
			StartTime: "00:00",
			EndTime:   "23:59",
			IPMasks:   []string{"0.0.0.0/0"},
		},
		SourceRules: rolestore.SourceRule{
			Type: "GROUP",
		},
		Comment:             "admins",
		PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
	}
}

func TestGetUserRolesHandler_Defaults(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 1,
			Items: []rolestore.Role{sampleRole()},
		}, nil
	})

	res, err := getUserRolesHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	items := m["items"].([]any)
	first := items[0].(map[string]any)
	if first["id"] != "r1" || first["name"] != "admin" {
		t.Errorf("item = %v", first)
	}
	context, ok := first["context"].(map[string]any)
	if !ok {
		t.Fatalf("context = %T", first["context"])
	}
	if context["enabled"] != true {
		t.Errorf("context.enabled = %v", context["enabled"])
	}
	if _, ok := context["timezone"]; ok {
		t.Error("timezone should not be in default context projection")
	}
	if _, ok := first["source_rules"]; ok {
		t.Error("source_rules should be absent by default")
	}
	if _, ok := first["comment"]; ok {
		t.Error("comment should be absent by default")
	}
}

func TestGetUserRolesHandler_SourceRulesAndContextFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 1,
			Items: []rolestore.Role{sampleRole()},
		}, nil
	})

	res, err := getUserRolesHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":            "u1",
		"sourceRules":   true,
		"contextFields": "timezone,ip_masks",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	first := m["items"].([]any)[0].(map[string]any)
	if _, ok := first["source_rules"]; !ok {
		t.Fatal("source_rules should be present when sourceRules=true")
	}
	context := first["context"].(map[string]any)
	if context["enabled"] != true {
		t.Errorf("enabled must remain from defaults, got %v", context["enabled"])
	}
	if context["timezone"] != "UTC" {
		t.Errorf("timezone = %v", context["timezone"])
	}
	if _, ok := context["ip_masks"]; ok {
		t.Error("ip_masks must be redacted even when requested")
	}
	if _, ok := context["start_time"]; ok {
		t.Error("start_time should not be projected unless requested")
	}
}

func TestGetUserRolesHandler_RawOverridesProjection(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return response.ResultSet[rolestore.Role]{
			Count: 1,
			Items: []rolestore.Role{sampleRole()},
		}, nil
	})

	res, err := getUserRolesHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":            "u1",
		"raw":           true,
		"sourceRules":   false,
		"contextFields": "timezone",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	first := m["items"].([]any)[0].(map[string]any)
	if first["comment"] != "admins" {
		t.Errorf("raw should include comment, got %v", first["comment"])
	}
	if _, ok := first["source_rules"]; !ok {
		t.Error("raw should include source_rules regardless of sourceRules flag")
	}
	context := first["context"].(map[string]any)
	if _, ok := context["start_time"]; !ok {
		t.Error("raw context should include full fields")
	}
	if _, ok := context["ip_masks"]; ok {
		t.Error("raw must still redact ip_masks")
	}
	if _, ok := first["principal_public_key_strings"]; ok {
		t.Error("raw must still redact principal_public_key_strings")
	}
}

func TestGetUserRolesHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getUserRolesHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetUserRolesHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id/roles", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := getUserRolesHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "failed to fetch user roles") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
