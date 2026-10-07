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
	targetdomaintools "github.com/pmsshintegration/privx-mcp/internal/tools/target_domains/tool"
	userstools "github.com/pmsshintegration/privx-mcp/internal/tools/users/tool"
	whitelisttools "github.com/pmsshintegration/privx-mcp/internal/tools/whitelists/tool"
)

// Register adds all tool topics to the registry.
func Register(reg registry.Registry, cfg *config.Config) {
	if cfg == nil {
		cfg = &config.Config{}
	}

	permissions := cfg.Permissions

	reg.Register(applyPermissions(filterTools(accessgrouptools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(apitargettools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(auditeventtools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(connectiontools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(hoststools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(networktargettools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(passwordpolicytools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(targetdomaintools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(whitelisttools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(rolestools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(statustools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(userstools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(requeststools.All(), permissions))...)
	reg.Register(applyPermissions(filterTools(infotools.All(infotools.SnapshotFromConfig(cfg)), permissions))...)
	reg.Register(applyPermissions(filterTools(echotools.TestTools(), permissions))...)
}

// applyPermissions populates each tool's RequiredPermissions from the central
// permission map, overriding any inline declaration. Tools not present in the
// map keep their existing (possibly empty) RequiredPermissions.
func applyPermissions(tools []registry.Tool) []registry.Tool {
	for i := range tools {
		if required := RequiredPermissionsForTool(tools[i].Name); required != nil {
			tools[i].RequiredPermissions = required
		}
	}

	return tools
}

func filterTools(all []registry.Tool, permissions config.PermissionsConfig) []registry.Tool {
	// Resolve order: default_read_only → whitelist → blacklist.
	readFiltered := filterReadOnlyTools(all, permissions.DefaultReadOnly)
	whitelisted := filterWhitelistedPrefixes(readFiltered, permissions.Whitelist)

	return filterBlacklistedPrefixes(whitelisted, permissions.Blacklist)
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
