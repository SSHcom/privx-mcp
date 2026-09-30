package network_targets

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func TestDefaultFieldSets(t *testing.T) {
	if len(DefaultNetworkTargetFields) == 0 {
		t.Fatal("DefaultNetworkTargetFields is empty")
	}
	if len(DefaultRoleFields) == 0 {
		t.Fatal("DefaultRoleFields is empty")
	}
	wantRoot := map[string]bool{"id": true, "name": true}
	for _, f := range DefaultRoleFields {
		if wantRoot[f] {
			delete(wantRoot, f)
		}
	}
	if len(wantRoot) != 0 {
		t.Errorf("DefaultRoleFields missing expected entries: %v", wantRoot)
	}
}

func TestSelectNetworkTargetFields_Defaults(t *testing.T) {
	target := networkaccessmanager.NetworkTarget{
		ID:   "nt1",
		Name: "t1",
		Tags: []string{"a"},
	}
	targetMap := utils.ToJSONMap(target)

	out := SelectNetworkTargetFields(targetMap, ProjectionFromParams(nil))
	for _, field := range DefaultNetworkTargetFields {
		v, ok := out[field]
		if !ok {
			t.Errorf("default field %q missing from projection", field)
			continue
		}
		if field == "id" && v != "nt1" {
			t.Errorf("id = %v", v)
		}
		if field == "name" && v != "t1" {
			t.Errorf("name = %v", v)
		}
	}
}

func TestSelectNetworkTargetFields_AbsentFieldsNull(t *testing.T) {
	out := SelectNetworkTargetFields(map[string]any{"id": "nt1"}, Projection{Root: []string{"id", "name", "roles"}, Roles: DefaultRoleFields})
	if out["id"] != "nt1" {
		t.Errorf("id = %v", out["id"])
	}
	if v, ok := out["name"]; !ok || v != nil {
		t.Errorf("name = %v ok=%v, want null", v, ok)
	}
	if v, ok := out["roles"]; !ok || v != nil {
		t.Errorf("roles = %v ok=%v, want null", v, ok)
	}
}

func TestSelectNetworkTargetFields_MalformedRoles(t *testing.T) {
	out := SelectNetworkTargetFields(map[string]any{"roles": []any{"x", 1, nil}}, Projection{Root: []string{"roles"}, Roles: DefaultRoleFields})
	roles, ok := out["roles"].([]any)
	if !ok {
		t.Fatalf("roles = %v", out["roles"])
	}
	if len(roles) != 0 {
		t.Errorf("len = %d, want 0", len(roles))
	}
}

func TestSelectNetworkTargetFields_ProjectsRoles(t *testing.T) {
	target := networkaccessmanager.NetworkTarget{
		ID:   "nt1",
		Name: "t1",
		Roles: []networkaccessmanager.RoleHandle{
			{ID: "r1", Name: "role-1"},
			{ID: "r2", Name: "role-2"},
		},
	}
	targetMap := utils.ToJSONMap(target)

	out := SelectNetworkTargetFields(targetMap, ProjectionFromParams(nil))
	roles, ok := out["roles"].([]any)
	if !ok {
		t.Fatalf("roles not a slice: %T", out["roles"])
	}
	if len(roles) != 2 {
		t.Fatalf("roles len = %d, want 2", len(roles))
	}
	for i, want := range []string{"r1", "r2"} {
		role, ok := roles[i].(map[string]any)
		if !ok {
			t.Fatalf("role[%d] not a map: %T", i, roles[i])
		}
		if role["id"] != want {
			t.Errorf("role[%d].id = %v, want %v", i, role["id"], want)
		}
		if _, hasName := role["name"]; !hasName {
			t.Errorf("role[%d].name missing", i)
		}
	}
}
