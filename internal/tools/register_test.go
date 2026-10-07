package tools

import (
	"reflect"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

func registerWithPermissions(reg registry.Registry, permissions config.PermissionsConfig) {
	Register(reg, &config.Config{Permissions: permissions})
}

func TestRegister_DefaultReadOnlySkipsWriteTools(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: true,
		Whitelist:       []string{"host-", "user-", "echo"},
	})

	_, hasCreateHost := reg.Get("host-create")
	if hasCreateHost {
		t.Fatal("expected host-create to be skipped in default read-only mode")
	}

	if _, hasListHosts := reg.Get("host-list"); !hasListHosts {
		t.Fatal("expected host-list to be registered in default read-only mode")
	}
	if _, hasListUsers := reg.Get("user-list"); !hasListUsers {
		t.Fatal("expected user-list to be registered in default read-only mode")
	}
	if _, hasTestEcho := reg.Get("echo"); !hasTestEcho {
		t.Fatal("expected echo to be registered in default read-only mode")
	}
}

func TestRegister_DefaultReadOnlyDisabledKeepsWriteTools(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: false,
		Whitelist:       []string{"host-create"},
	})

	if _, hasCreateHost := reg.Get("host-create"); !hasCreateHost {
		t.Fatal("expected host-create to be registered when default read-only is disabled")
	}
	if _, hasListHosts := reg.Get("host-list"); hasListHosts {
		t.Fatal("expected host-list to be filtered out by whitelist")
	}
}

func TestRegister_EmptyWhitelistSkipsPrefixFiltering(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: false,
		Whitelist:       []string{},
	})

	if _, hasListHosts := reg.Get("host-list"); !hasListHosts {
		t.Fatal("expected host-list to remain when whitelist is empty")
	}
	if _, hasListUsers := reg.Get("user-list"); !hasListUsers {
		t.Fatal("expected user-list to remain when whitelist is empty")
	}
}

func TestRegister_RequestToolsReadOnlyAndWhitelist(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: true,
		Whitelist:       []string{"request-"},
	})

	if _, ok := reg.Get("request-list"); !ok {
		t.Fatal("expected request-list")
	}
	if _, ok := reg.Get("request-get"); !ok {
		t.Fatal("expected request-get")
	}
	if _, ok := reg.Get("request-search"); !ok {
		t.Fatal("expected request-search")
	}
	if _, ok := reg.Get("request-create"); ok {
		t.Fatal("expected request-create to be skipped in default read-only mode")
	}
	if _, ok := reg.Get("request-delete"); ok {
		t.Fatal("expected request-delete to be skipped in default read-only mode")
	}
	if _, ok := reg.Get("request-revoke-role"); ok {
		t.Fatal("expected request-revoke-role to be skipped in default read-only mode")
	}
}

func TestRegister_BlacklistAppliedAfterWhitelist(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: false,
		Whitelist: []string{
			"host-list", "host-get", "host-search",
			"user-list", "user-get", "user-search", "user-get-roles",
		},
		Blacklist: []string{"user-list", "user-search", "host-search"},
	})

	if _, hasListHosts := reg.Get("host-list"); !hasListHosts {
		t.Fatal("expected host-list to remain after blacklist")
	}
	if _, hasGetUser := reg.Get("user-get"); !hasGetUser {
		t.Fatal("expected user-get to remain after blacklist")
	}
	if _, hasListUsers := reg.Get("user-list"); hasListUsers {
		t.Fatal("expected user-list to be removed by blacklist")
	}
	if _, hasSearchUsers := reg.Get("user-search"); hasSearchUsers {
		t.Fatal("expected user-search to be removed by blacklist")
	}
	if _, hasCreateHost := reg.Get("host-create"); hasCreateHost {
		t.Fatal("expected host-create to remain filtered out by whitelist")
	}
}

func TestRegister_EmptyBlacklistKeepsWhitelistedTools(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: false,
		Whitelist:       []string{"host-list", "user-list"},
		Blacklist:       []string{},
	})

	if _, hasListHosts := reg.Get("host-list"); !hasListHosts {
		t.Fatal("expected host-list to remain when blacklist is empty")
	}
	if _, hasListUsers := reg.Get("user-list"); !hasListUsers {
		t.Fatal("expected user-list to remain when blacklist is empty")
	}
}

func TestRegister_BlacklistAlone(t *testing.T) {
	reg := registry.NewRegistry()

	registerWithPermissions(reg, config.PermissionsConfig{
		DefaultReadOnly: false,
		Blacklist:       []string{"host-delete", "host-create", "user-delete-", "user-create-"},
	})

	if _, hasListHosts := reg.Get("host-list"); !hasListHosts {
		t.Fatal("expected host-list to remain when only blacklist is set")
	}
	if _, hasCreateHost := reg.Get("host-create"); hasCreateHost {
		t.Fatal("expected host-create to be removed by blacklist")
	}
	if _, hasDeleteHost := reg.Get("host-delete"); hasDeleteHost {
		t.Fatal("expected host-delete to be removed by blacklist")
	}
}

// TestRegister_RequiredPermissionsConsistency asserts that after a full
// unfiltered Register, every registered tool (except the unmapped echo
// test tool) carries the RequiredPermissions resolved from the central
// permission map, and that every name in the permission map is actually
// registered. This catches both unmapped implemented tools and stale
// map entries referencing unimplemented tools.
func TestRegister_RequiredPermissionsConsistency(t *testing.T) {
	reg := registry.NewRegistry()
	registerWithPermissions(reg, config.PermissionsConfig{DefaultReadOnly: false})

	for _, tool := range reg.Tools() {
		if tool.Name == "echo" {
			if len(tool.RequiredPermissions) != 0 {
				t.Errorf("echo should have no required permissions, got %v", tool.RequiredPermissions)
			}
			continue
		}
		want := RequiredPermissionsForTool(tool.Name)
		if !reflect.DeepEqual(tool.RequiredPermissions, want) {
			t.Errorf("tool %q: RequiredPermissions = %v, want %v", tool.Name, tool.RequiredPermissions, want)
		}
	}

	registered := make(map[string]bool)
	for _, tool := range reg.Tools() {
		registered[tool.Name] = true
	}
	for scope, names := range toolsByPermission {
		for _, name := range names {
			if !registered[name] {
				t.Errorf("permission scope %q lists %q which is not registered", scope, name)
			}
		}
	}
}

// TestRegister_OneToolPerTopic smoke-tests that one representative tool
// from each topic wired in register.go is registered, so a forgotten
// reg.Register(...) fails loudly.
func TestRegister_OneToolPerTopic(t *testing.T) {
	reg := registry.NewRegistry()
	registerWithPermissions(reg, config.PermissionsConfig{DefaultReadOnly: false})

	topics := []string{
		"access-group-list",
		"api-target-list",
		"audit-event-list",
		"status-components",
		"connection-list",
		"host-list",
		"network-target-list",
		"password-policy-list",
		"target-domain-list",
		"whitelist-list",
		"role-list",
		"user-list",
		"request-list",
		"mcp-info",
		"echo",
	}
	for _, name := range topics {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("expected %q to be registered (one tool per topic smoke)", name)
		}
	}
}
