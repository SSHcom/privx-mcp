package users

import (
	"encoding/json"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
)

func TestSelectUserFields_DefaultsPreserveNullRoles(t *testing.T) {
	user := map[string]any{
		"id":          "u1",
		"principal":   "alice",
		"source":      "src-1",
		"source_type": "AD",
		"full_name":   "Alice",
		"roles":       nil,
		"extra":       "dropped",
	}
	out := SelectUserFields(user, ProjectionFromParams(nil))
	if _, ok := out["extra"]; ok {
		t.Error("extra field should be dropped")
	}
	if out["id"] != "u1" {
		t.Errorf("id = %v", out["id"])
	}
	if out["principal"] != "alice" {
		t.Errorf("principal = %v", out["principal"])
	}
	if v, ok := out["roles"]; !ok {
		t.Fatal("roles key must be present")
	} else if v != nil {
		t.Errorf("roles = %v, want null", v)
	}
	if v, ok := out["email"]; !ok {
		t.Fatal("email key must be present when requested")
	} else if v != nil {
		t.Errorf("missing email should be null, got %v", v)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["roles"] != nil {
		t.Errorf("JSON roles = %v, want null", decoded["roles"])
	}
}

func TestSelectUserFields_RolesProjected(t *testing.T) {
	user := map[string]any{
		"id": "u1",
		"roles": []any{
			map[string]any{"id": "r1", "name": "admin", "comment": "x"},
			map[string]any{"id": "r2", "name": "viewer"},
		},
	}
	out := SelectUserFields(user, Projection{Root: []string{"id", "roles"}, Roles: DefaultRoleFields})
	roles, ok := out["roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Fatalf("roles = %v", out["roles"])
	}
	role, ok := roles[0].(map[string]any)
	if !ok {
		t.Fatalf("role not a map: %T", roles[0])
	}
	if role["id"] != "r1" || role["name"] != "admin" {
		t.Errorf("role = %v", role)
	}
	if _, ok := role["comment"]; ok {
		t.Error("comment should not be projected by default role fields")
	}
}

func TestSelectUserFields_MalformedRoles(t *testing.T) {
	out := SelectUserFields(map[string]any{"id": "u1", "roles": "not-an-array"}, Projection{Root: []string{"roles"}, Roles: DefaultRoleFields})
	if out["roles"] != nil {
		t.Errorf("malformed roles = %v, want null", out["roles"])
	}
}

func TestSelectUserFields_RolesNullNotEmptyArray(t *testing.T) {
	out := SelectUserFields(map[string]any{"id": "u1"}, Projection{Root: []string{"roles"}, Roles: DefaultRoleFields})
	if out["roles"] != nil {
		t.Errorf("absent roles = %v, want null (not [])", out["roles"])
	}
}

func TestRedactSensitiveUserFields(t *testing.T) {
	user := map[string]any{
		"id":                   "u1",
		"password":             "secret",
		"settings":             map[string]any{"a": 1},
		"authorized_keys":      []any{"k"},
		"webauthn_credentials": []any{"c"},
		"principal":            "alice",
		"mfa": map[string]any{
			"status": "enabled",
			"seed":   map[string]any{"seed_string": "SECRET"},
		},
		"attributes": []any{
			map[string]any{"key": "windows_sid", "value": "S-1-5"},
			map[string]any{"key": "department", "value": "ops"},
		},
		"roles": []any{
			map[string]any{
				"id":                           "r1",
				"name":                         "admin",
				"principal_public_key_strings": []any{"ssh-ed25519 AAAA"},
				"context":                      map[string]any{"enabled": true, "ip_masks": []any{"10.0.0.0/8"}},
			},
		},
	}
	out := RedactSensitiveUserFields(user)
	for _, field := range []string{"password", "settings", "authorized_keys", "webauthn_credentials"} {
		if _, ok := out[field]; ok {
			t.Errorf("%s should be redacted", field)
		}
	}
	mfa := out["mfa"].(map[string]any)
	if _, ok := mfa["seed"]; ok {
		t.Error("mfa.seed should be redacted")
	}
	if mfa["status"] != "enabled" {
		t.Errorf("mfa status should remain, got %v", mfa["status"])
	}
	attrs := out["attributes"].([]any)
	if len(attrs) != 1 || attrs[0].(map[string]any)["key"] != "department" {
		t.Errorf("attributes = %v", attrs)
	}
	if out["principal"] != "alice" {
		t.Errorf("principal = %v", out["principal"])
	}
	role := out["roles"].([]any)[0].(map[string]any)
	if _, ok := role["principal_public_key_strings"]; ok {
		t.Error("principal_public_key_strings should be redacted from roles")
	}
	if role["name"] != "admin" {
		t.Errorf("role name should remain, got %v", role["name"])
	}
	context := role["context"].(map[string]any)
	if _, ok := context["ip_masks"]; ok {
		t.Error("roles[].context.ip_masks should be redacted")
	}
	if context["enabled"] != true {
		t.Errorf("role context.enabled should remain, got %v", context["enabled"])
	}
}

func TestFormatUserItems_RawRedactsRolePublicKeys(t *testing.T) {
	items := []rolestore.User{
		{
			ID:        "u1",
			Principal: "alice",
			Roles: []rolestore.Role{{
				ID:                  "r1",
				Name:                "admin",
				PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
			}},
		},
	}
	out := FormatUserItems(items, true, Projection{})
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	roles, ok := out[0]["roles"].([]any)
	if !ok || len(roles) != 1 {
		t.Fatalf("roles = %v", out[0]["roles"])
	}
	role := roles[0].(map[string]any)
	if _, ok := role["principal_public_key_strings"]; ok {
		t.Error("raw must still redact principal_public_key_strings")
	}
	if role["id"] != "r1" {
		t.Errorf("role id = %v", role["id"])
	}
}

func TestSelectUserFields_ExplicitRolePublicKeysStillRedacted(t *testing.T) {
	items := []rolestore.User{
		{
			ID: "u1",
			Roles: []rolestore.Role{{
				ID:                  "r1",
				Name:                "admin",
				PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
			}},
		},
	}
	out := FormatUserItems(items, false, Projection{
		Root:  []string{"id", "roles"},
		Roles: []string{"id", "name", "principal_public_key_strings"},
	})
	roles := out[0]["roles"].([]any)
	role := roles[0].(map[string]any)
	if _, ok := role["principal_public_key_strings"]; ok {
		t.Error("explicit roleFields must still redact principal_public_key_strings")
	}
}

func TestFormatUserItems_RawStillRedacts(t *testing.T) {
	items := []rolestore.User{
		{ID: "u1", Principal: "alice", Password: "secret"},
	}
	out := FormatUserItems(items, true, Projection{})
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	if _, ok := out[0]["password"]; ok {
		t.Error("raw must still redact password")
	}
	if out[0]["principal"] != "alice" {
		t.Errorf("principal = %v", out[0]["principal"])
	}
}

func TestFormatUserItems_ProjectedDefaults(t *testing.T) {
	items := []rolestore.User{
		{ID: "u1", Principal: "alice", SourceType: "LOCAL", FullName: "Alice"},
	}
	out := FormatUserItems(items, false, ProjectionFromParams(nil))
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	u := out[0]
	if u["id"] != "u1" || u["principal"] != "alice" {
		t.Errorf("got %#v", u)
	}
	if _, ok := u["roles"]; !ok {
		t.Fatal("roles must be present")
	}
	if u["roles"] != nil {
		t.Errorf("roles = %v, want null", u["roles"])
	}
	if _, ok := u["email"]; !ok {
		t.Fatal("email must be present as null when empty")
	}
}

func TestSelectUserRoleFields_Defaults(t *testing.T) {
	role := map[string]any{
		"id":      "r1",
		"name":    "admin",
		"comment": "x",
		"context": map[string]any{
			"enabled":  true,
			"timezone": "UTC",
		},
		"source_rules": map[string]any{"type": "GROUP"},
	}
	out := SelectUserRoleFields(role, false, DefaultUserRoleContextFields)
	if out["id"] != "r1" || out["name"] != "admin" {
		t.Errorf("got %#v", out)
	}
	if _, ok := out["comment"]; ok {
		t.Error("comment should be dropped")
	}
	if _, ok := out["source_rules"]; ok {
		t.Error("source_rules should be absent when not requested")
	}
	context := out["context"].(map[string]any)
	if context["enabled"] != true {
		t.Errorf("enabled = %v", context["enabled"])
	}
	if _, ok := context["timezone"]; ok {
		t.Error("timezone should not be in default context fields")
	}
}

func TestSelectUserRoleFields_SourceRulesAndContextFields(t *testing.T) {
	role := map[string]any{
		"id":   "r1",
		"name": "admin",
		"context": map[string]any{
			"enabled":    false,
			"timezone":   "UTC",
			"start_time": "00:00",
		},
		"source_rules": map[string]any{"type": "GROUP"},
	}
	out := SelectUserRoleFields(role, true, []string{"enabled", "timezone"})
	if out["source_rules"] == nil {
		t.Fatal("source_rules should be included")
	}
	context := out["context"].(map[string]any)
	if _, ok := context["start_time"]; ok {
		t.Error("start_time should not be projected")
	}
	if context["timezone"] != "UTC" {
		t.Errorf("timezone = %v", context["timezone"])
	}
}

func TestFormatUserRoleItems_RawStillRedacts(t *testing.T) {
	items := []rolestore.Role{{
		ID:                  "r1",
		Name:                "admin",
		PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
		Comment:             "note",
	}}
	out := FormatUserRoleItems(items, true, false, nil)
	if len(out) != 1 {
		t.Fatalf("len = %d", len(out))
	}
	if _, ok := out[0]["principal_public_key_strings"]; ok {
		t.Error("raw must still redact principal_public_key_strings")
	}
	if out[0]["comment"] != "note" {
		t.Errorf("comment = %v", out[0]["comment"])
	}
}
