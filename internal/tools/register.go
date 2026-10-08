// Package tools provides the top-level tool registration entrypoint.
package tools

import (
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	accessgrouptools "github.com/pmsshintegration/privx-mcp/internal/tools/access_groups/tool"
	apitargettools "github.com/pmsshintegration/privx-mcp/internal/tools/api_targets/tool"
	auditeventtools "github.com/pmsshintegration/privx-mcp/internal/tools/audit_events/tool"
	connectiontools "github.com/pmsshintegration/privx-mcp/internal/tools/connections/tool"
	echotools "github.com/pmsshintegration/privx-mcp/internal/tools/echo"
	hoststools "github.com/pmsshintegration/privx-mcp/internal/tools/hosts/tool"
	infotools "github.com/pmsshintegration/privx-mcp/internal/tools/info"
	networktargettools "github.com/pmsshintegration/privx-mcp/internal/tools/network_targets/tool"
	passwordpolicytools "github.com/pmsshintegration/privx-mcp/internal/tools/password_policies/tool"
	requeststools "github.com/pmsshintegration/privx-mcp/internal/tools/requests/tool"
	rolestools "github.com/pmsshintegration/privx-mcp/internal/tools/roles/tool"
	statustools "github.com/pmsshintegration/privx-mcp/internal/tools/status/tool"
	userstools "github.com/pmsshintegration/privx-mcp/internal/tools/users/tool"
	whitelisttools "github.com/pmsshintegration/privx-mcp/internal/tools/whitelists/tool"
)

// Register adds all tool topics to the registry.
func Register(reg registry.Registry, cfg *config.Config) {
	if cfg == nil {
		cfg = &config.Config{}
	}

	permissions := cfg.Permissions

	register := func(tools []registry.Tool) {
		reg.Register(applyPermissions(filterTools(tools, permissions), permissions)...)
	}

	register(accessgrouptools.All())
	register(apitargettools.All())
	register(auditeventtools.All())
	register(connectiontools.All())
	register(hoststools.All())
	register(networktargettools.All())
	register(passwordpolicytools.All())
	register(whitelisttools.All())
	register(rolestools.All())
	register(statustools.All())
	register(userstools.All())
	register(requeststools.All())
	register(infotools.All(infotools.SnapshotFromConfig(cfg)))
	register(echotools.TestTools())
}

// applyPermissions populates each tool's RequiredPermissions from the central
// permission map, overriding any inline declaration. Tools not present in the
// map keep their existing (possibly empty) RequiredPermissions.
//
// Sensitive tools are special-cased: unless non-admin access is explicitly
// enabled, they require the privx-admin scope so that only privx-admin role
// holders can see or call them, regardless of their granular scopes in the
// central map.
func applyPermissions(tools []registry.Tool, permissions config.PermissionsConfig) []registry.Tool {
	for i := range tools {
		if tools[i].Sensitive && !permissions.SensitiveDataToolsAllowNonAdmin {
			tools[i].RequiredPermissions = []string{PermissionPrivxAdmin}
			continue
		}

		if required := RequiredPermissionsForTool(tools[i].Name); required != nil {
			tools[i].RequiredPermissions = required
		}
	}

	return tools
}

func filterTools(all []registry.Tool, permissions config.PermissionsConfig) []registry.Tool {
	// Resolve order: sensitive gate → default_read_only → whitelist → blacklist.
	sensitiveFiltered := filterSensitiveTools(all, permissions.EnableSensitiveDataTools)
	readFiltered := filterReadOnlyTools(sensitiveFiltered, permissions.DefaultReadOnly)
	whitelisted := filterWhitelistedPrefixes(readFiltered, permissions.Whitelist)

	return filterBlacklistedPrefixes(whitelisted, permissions.Blacklist)
}

// filterSensitiveTools drops tools marked Sensitive unless the operator has
// explicitly enabled sensitive-data tools. This is the outermost gate: a
// sensitive tool that is not enabled is never registered, listed, or callable.
func filterSensitiveTools(all []registry.Tool, enabled bool) []registry.Tool {
	if enabled {
		return all
	}

	filtered := make([]registry.Tool, 0, len(all))
	for _, tool := range all {
		if tool.Sensitive {
			continue
		}

		filtered = append(filtered, tool)
	}

	return filtered
}

func filterReadOnlyTools(all []registry.Tool, defaultReadOnly bool) []registry.Tool {
	if !defaultReadOnly {
		return all
	}

	filtered := make([]registry.Tool, 0, len(all))
	for _, tool := range all {
		if tool.Writes {
			continue
		}

		filtered = append(filtered, tool)
	}

	return filtered
}

func filterWhitelistedPrefixes(all []registry.Tool, whitelist []string) []registry.Tool {
	if len(whitelist) == 0 {
		return all
	}

	filtered := make([]registry.Tool, 0, len(all))
	for _, tool := range all {
		if matchesAnyPrefix(tool.Name, whitelist) {
			filtered = append(filtered, tool)
		}
	}

	return filtered
}

func filterBlacklistedPrefixes(all []registry.Tool, blacklist []string) []registry.Tool {
	if len(blacklist) == 0 {
		return all
	}

	filtered := make([]registry.Tool, 0, len(all))
	for _, tool := range all {
		if matchesAnyPrefix(tool.Name, blacklist) {
			continue
		}

		filtered = append(filtered, tool)
	}

	return filtered
}

func matchesAnyPrefix(toolName string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(toolName, prefix) {
			return true
		}
	}

	return false
}
