// Package common holds shared MCP tool defaults and helpers.
package common

// Default and maximum page sizes for list/search MCP tools.
// Maxima follow the PrivX item shape: nested arrays (host services and
// principals, raw connection host/user blobs) stay small; flat rows can be larger.
const (
	HostsListLimit = 20
	HostsListMax   = 40

	UsersListLimit = 50
	UsersListMax   = 100

	RolesListLimit = 100
	RolesListMax   = 200

	RequestsListLimit = 100
	RequestsListMax   = 200

	NetworkTargetsListLimit = 50
	NetworkTargetsListMax   = 100

	APITargetsListLimit = 50
	APITargetsListMax   = 100

	TargetDomainsListLimit = 50
	TargetDomainsListMax   = 100

	AuditEventsListLimit = 100
	AuditEventsListMax   = 200

	ConnectionsListLimit = 25
	ConnectionsListMax   = 25

	ConnectionTrailListLimit = 100
	ConnectionTrailListMax   = 100

	WhitelistsListLimit = 50
	WhitelistsListMax   = 100
)
