package tools

import (
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

func TestRequiredPermissionsForTool_PrefersViewOverManage(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"host-list", PermissionHostsView},
		{"host-get", PermissionHostsView},
		{"host-search", PermissionAuthenticated},
		{"host-create", PermissionHostsManage},
		{"host-update", PermissionHostsManage},
		{"host-delete", PermissionHostsManage},
		{"user-list", PermissionUsersView},
		{"user-create-local", PermissionUsersManage},
		{"request-list", PermissionWorkflowsRequests},
		{"request-create", PermissionWorkflowsRequests},
		{"request-set-decision", PermissionWorkflowsRequests},
		{"network-target-list", PermissionNetworkTargetsView},
		{"network-target-get", PermissionNetworkTargetsView},
		{"network-target-search", PermissionNetworkTargetsView},
		{"network-target-create", PermissionNetworkTargetsManage},
		{"network-target-update", PermissionNetworkTargetsManage},
		{"network-target-delete", PermissionNetworkTargetsManage},
		{"api-target-list", PermissionAPITargetsView},
		{"api-target-get", PermissionAPITargetsView},
		{"api-target-delete", PermissionAPITargetsManage},
		{"audit-event-codes", PermissionLogsView},
		{"audit-event-list", PermissionLogsView},
		{"audit-event-search", PermissionLogsView},
		{"status-components", PermissionLogsView},
		{"status-instance", PermissionLogsView},
		{"status-monitor-service", PermissionLogsView},

		{"role-list", PermissionRolesView},
		{"role-create", PermissionRolesManage},

		{"connection-list", PermissionConnectionsView},
		{"connection-terminate", PermissionConnectionsTerminate},

		{"access-group-list", PermissionAccessGroupsManage},
		{"access-group-create", PermissionAccessGroupsManage},

		{"password-policy-list", PermissionPrivxAdmin},
		{"whitelist-list", PermissionPrivxAdmin},
		{"whitelist-evaluate", PermissionPrivxAdmin},
	}
	for _, tc := range cases {
		got := RequiredPermissionsForTool(tc.tool)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("tool %q: got %v, want [%s]", tc.tool, got, tc.want)
		}
	}
}

func TestRequiredPermissionsForTool_Unknown(t *testing.T) {
	if got := RequiredPermissionsForTool("does-not-exist"); got != nil {
		t.Fatalf("expected nil for unknown tool, got %v", got)
	}
	// Unimplemented names (e.g. mcp-guidelines) are not in the map and
	// therefore resolve to nil, just like any other unknown tool.
	if got := RequiredPermissionsForTool("mcp-guidelines"); got != nil {
		t.Fatalf("expected nil for unimplemented name, got %v", got)
	}
}

func TestRequiredPermissionsForTool_AuthenticatedInfo(t *testing.T) {
	got := RequiredPermissionsForTool("mcp-info")
	if len(got) != 1 || got[0] != PermissionAuthenticated {
		t.Fatalf("mcp-info RequiredPermissions = %v, want [%s]", got, PermissionAuthenticated)
	}
}

func TestPermissionTools(t *testing.T) {
	got := permissionTools(PermissionHostsView)
	if len(got) == 0 {
		t.Fatal("expected host view tools")
	}
	found := false
	for _, name := range got {
		if name == "host-list" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("permissionTools(%s) missing host-list: %v", PermissionHostsView, got)
	}

	// Returned slice must be a copy.
	got[0] = "mutated"
	again := permissionTools(PermissionHostsView)
	if again[0] == "mutated" {
		t.Fatal("permissionTools should return a copy")
	}

	if permissionTools("does-not-exist") != nil {
		t.Fatal("expected nil for unknown permission")
	}
}

func TestAllPermissionScopes(t *testing.T) {
	scopes := allPermissionScopes()
	if len(scopes) == 0 {
		t.Fatal("expected permission scopes")
	}
	want := map[string]bool{
		PermissionHostsView:     false,
		PermissionHostsManage:   false,
		PermissionAuthenticated: false,
	}
	for _, scope := range scopes {
		if _, ok := want[scope]; ok {
			want[scope] = true
		}
	}
	for scope, seen := range want {
		if !seen {
			t.Errorf("missing scope %q in %v", scope, scopes)
		}
	}
}

func TestRegister_AppliesRequiredPermissionsFromMap(t *testing.T) {
	reg := registry.NewRegistry()
	Register(reg, &config.Config{
		Permissions: config.PermissionsConfig{
			DefaultReadOnly: false,
		},
	})

	tool, ok := reg.Get("host-list")
	if !ok {
		t.Fatal("expected host-list to be registered")
	}
	if len(tool.RequiredPermissions) != 1 || tool.RequiredPermissions[0] != PermissionHostsView {
		t.Fatalf("host-list RequiredPermissions = %v, want [%s]", tool.RequiredPermissions, PermissionHostsView)
	}

	create, ok := reg.Get("host-create")
	if !ok {
		t.Fatal("expected host-create to be registered")
	}
	if len(create.RequiredPermissions) != 1 || create.RequiredPermissions[0] != PermissionHostsManage {
		t.Fatalf("host-create RequiredPermissions = %v, want [%s]", create.RequiredPermissions, PermissionHostsManage)
	}

	info, ok := reg.Get("mcp-info")
	if !ok {
		t.Fatal("expected mcp-info to be registered")
	}
	if len(info.RequiredPermissions) != 1 || info.RequiredPermissions[0] != PermissionAuthenticated {
		t.Fatalf("mcp-info RequiredPermissions = %v, want [%s]", info.RequiredPermissions, PermissionAuthenticated)
	}
}
