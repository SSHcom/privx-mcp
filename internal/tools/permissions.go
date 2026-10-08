// Package tools centralizes MCP tool permission mapping.
//
// The permission map is the single source of truth for which PrivX permission
// scope is required to invoke each MCP tool. Tool definitions no longer carry
// their own RequiredPermissions value; instead, the registry wiring resolves
// requirements from this map at registration time.
//
// Naming convention: keys and tool names are lowercase, hyphenated, resource-
// first, and use no privx_ prefix (e.g. privx_list_hosts -> host-list,
// hostsView -> hosts-view).
package tools

import (
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

// Permission scope names. The special authenticated/public scopes are shared
// constants from the registry package so the runtime can reference them too.
const (
	PermissionHostsView            = "hosts-view"
	PermissionHostsManage          = "hosts-manage"
	PermissionRolesView            = "roles-view"
	PermissionRolesManage          = "roles-manage"
	PermissionUsersView            = "users-view"
	PermissionUsersManage          = "users-manage"
	PermissionConnectionsView      = "connections-view"
	PermissionConnectionsManage    = "connections-manage"
	PermissionConnectionsTerminate = "connections-terminate"
	PermissionConnectionsTrail     = "connections-trail"
	PermissionPrivxAdmin           = "privx-admin"
	PermissionLogsView             = "logs-view"
	PermissionWorkflowsRequests    = "workflows-requests"
	PermissionNetworkTargetsView   = "network-targets-view"
	PermissionNetworkTargetsManage = "network-targets-manage"
	PermissionAPITargetsView       = "api-targets-view"
	PermissionAPITargetsManage     = "api-targets-manage"
	PermissionAccessGroupsManage   = "access-groups-manage"

	PermissionAuthenticated = registry.PermissionAuthenticated
	PermissionPublic        = registry.PermissionPublic
)

// View- and write-scope tool groups. Manage scopes compose the two via
// toolsByPermission in init().
var (
	// Hosts
	hostsViewTools = []string{
		"host-list",
		"host-get",
		// host-search is enabled for all authenticated users.
		// Users without hosts-view permission can only see hosts they have access to.
	}
	hostsWriteTools = []string{
		"host-create",
		"host-update",
		"host-delete",
	}

	// Roles
	rolesViewTools = []string{
		"role-list",
		"role-get",
		"role-members",
	}
	rolesWriteTools = []string{
		"role-create",
		"role-update",
		"role-delete",
		"role-grant",
		"role-revoke",
	}

	// Users
	usersViewTools = []string{
		"user-list",
		"user-get",
		"user-search",
		"user-get-roles",
	}
	usersWriteTools = []string{
		"user-create-local",
		"user-update-local",
		"user-delete-local",
	}

	// Connections
	connectionsViewTools = []string{
		"connection-list",
		"connection-get",
		"connection-search",
	}
	connectionsTerminateTools = []string{
		"connection-terminate",
	}
	// connection-trail-get requires BOTH connections-view and connections-trail
	// (see trailRequiredPermissionOverrides). It is listed here so the trail
	// scope grants it and so registration coverage checks pass.
	connectionsTrailTools = []string{
		"connection-trail-get",
	}

	// Logs / audit events and monitor-service status
	logsViewTools = []string{
		"audit-event-codes",
		"audit-event-list",
		"audit-event-search",
		"status-components",
		"status-instance",
		"status-monitor-service",
	}

	// Workflow access requests (user actions on /requests)
	// workflows-requests: user can manage their own requests and approve/deny
	// requests waiting for their role's approval
	// workflows-requests-on-behalf: user can create requests for others
	workflowsRequestsTools = []string{
		"request-list",
		"request-search",
		"request-get",
		"request-create",
		"request-delete",
		"request-set-decision",
		"request-revoke-role",
	}
	// No separate admin tools — all request tools are user-level.
	// Workflow admin (CRUD on /workflows) will be a separate tool set.

	// Network targets
	networkTargetsViewTools = []string{
		"network-target-list",
		"network-target-get",
		"network-target-search",
	}
	networkTargetsWriteTools = []string{
		"network-target-create",
		"network-target-update",
		"network-target-delete",
	}

	// API targets
	apiTargetsViewTools = []string{
		"api-target-list",
		"api-target-get",
	}
	apiTargetsWriteTools = []string{
		"api-target-delete",
	}

	// Password policies (admin-only, no specific PrivX permission)
	passwordPoliciesTools = []string{
		"password-policy-list",
		"password-policy-get",
		"password-policy-create",
		"password-policy-update",
		"password-policy-delete",
	}

	// Command whitelists (admin-only)
	commandWhitelistsTools = []string{
		"whitelist-list",
		"whitelist-get",
		"whitelist-search",
		"whitelist-create",
		"whitelist-update",
		"whitelist-delete",
		"whitelist-evaluate",
	}

	// Access groups
	accessGroupsTools = []string{
		"access-group-list",
		"access-group-get",
		"access-group-create",
		"access-group-update",
		"access-group-delete",
	}
)

// toolsByPermission maps each permission scope to the MCP tool names it grants
// access to. Manage scopes include all tools from their corresponding view
// scope plus their own write-capable tools.
var toolsByPermission map[string][]string

// toolRequiredPermissions is the reverse map used at registration time.
// View tools require the view scope (not manage), even though manage also
// grants those tools at evaluation time.
var toolRequiredPermissions map[string][]string

func init() {
	toolsByPermission = map[string][]string{
		PermissionHostsView:   hostsViewTools,
		PermissionHostsManage: concat(hostsWriteTools, hostsViewTools),

		PermissionRolesView:   rolesViewTools,
		PermissionRolesManage: concat(rolesWriteTools, rolesViewTools),

		PermissionUsersView:   usersViewTools,
		PermissionUsersManage: concat(usersWriteTools, usersViewTools),

		PermissionConnectionsView:      connectionsViewTools,
		PermissionConnectionsManage:    concat(connectionsTerminateTools, connectionsTrailTools, connectionsViewTools),
		PermissionConnectionsTerminate: connectionsTerminateTools,
		PermissionConnectionsTrail:     connectionsTrailTools,

		PermissionLogsView: logsViewTools,

		PermissionWorkflowsRequests: workflowsRequestsTools,

		PermissionNetworkTargetsView:   networkTargetsViewTools,
		PermissionNetworkTargetsManage: concat(networkTargetsWriteTools, networkTargetsViewTools),

		PermissionAPITargetsView:   apiTargetsViewTools,
		PermissionAPITargetsManage: concat(apiTargetsWriteTools, apiTargetsViewTools),

		PermissionPrivxAdmin: concat(passwordPoliciesTools, commandWhitelistsTools),

		PermissionAccessGroupsManage: accessGroupsTools,

		PermissionAuthenticated: {
			"mcp-info",
			"host-search",
		},
	}

	toolRequiredPermissions = buildToolRequiredPermissions(toolsByPermission)

	// Apply explicit multi-scope requirements. buildToolRequiredPermissions
	// derives a single least-privilege scope per tool, so tools that require
	// more than one scope (AND semantics, enforced by the runtime) are declared
	// here and override the derived value.
	for name, scopes := range toolRequiredPermissionOverrides {
		toolRequiredPermissions[name] = append([]string(nil), scopes...)
	}
}

// toolRequiredPermissionOverrides declares tools that require more than one
// permission scope. The runtime requires ALL listed scopes (AND). connection-
// trail-get needs connections-view (to find/read the connection) plus
// connections-trail (to read its recorded session content).
var toolRequiredPermissionOverrides = map[string][]string{
	"connection-trail-get": {PermissionConnectionsView, PermissionConnectionsTrail},
}

// buildToolRequiredPermissions builds tool → required-scope. When a tool
// appears under both a view and manage scope, the view scope wins so
// registration asks for the least privilege that grants the tool.
func buildToolRequiredPermissions(scopes map[string][]string) map[string][]string {
	out := make(map[string][]string)

	for scope, toolNames := range scopes {
		if scope == PermissionPublic {
			continue
		}

		for _, name := range toolNames {
			existing, ok := out[name]
			if !ok {
				out[name] = []string{scope}
				continue
			}

			incomingManage := isManageScope(scope)
			existingManage := isManageScope(existing[0])
			// Prefer non-manage over manage (least privilege).
			if incomingManage && !existingManage {
				continue
			}

			if !incomingManage && existingManage {
				out[name] = []string{scope}
				continue
			}

			bothView := !incomingManage && !existingManage
			// Both non-manage: prefer the scope whose name contains
			// "requests" (more specific) over generic "view".
			if bothView && isRequestsScope(scope) {
				out[name] = []string{scope}
			}
		}
	}

	return out
}

func isManageScope(scope string) bool {
	return strings.HasSuffix(scope, "-manage")
}

func isRequestsScope(scope string) bool {
	return strings.HasSuffix(scope, "-requests")
}

// permissionTools returns a copy of the tool names granted by the given
// permission scope. The returned slice is safe to modify.
func permissionTools(permission string) []string {
	tools, ok := toolsByPermission[permission]
	if !ok {
		return nil
	}

	return append([]string(nil), tools...)
}

// allPermissionScopes returns every permission scope known to the map,
// including the special authenticated and public scopes.
func allPermissionScopes() []string {
	scopes := make([]string, 0, len(toolsByPermission))
	for scope := range toolsByPermission {
		scopes = append(scopes, scope)
	}

	return scopes
}

// RequiredPermissionsForTool returns the permission scopes required to invoke
// the given tool. Most tools map to a single scope; tools listed under
// PermissionPublic return nil (no requirement). View tools require the view
// scope even though the matching manage scope also grants them.
func RequiredPermissionsForTool(toolName string) []string {
	required, ok := toolRequiredPermissions[toolName]
	if !ok {
		return nil
	}

	return append([]string(nil), required...)
}

// concat returns a new slice holding the concatenation of the given slices.
func concat(parts ...[]string) []string {
	total := 0
	for _, p := range parts {
		total += len(p)
	}

	combined := make([]string, 0, total)
	for _, p := range parts {
		combined = append(combined, p...)
	}

	return combined
}
