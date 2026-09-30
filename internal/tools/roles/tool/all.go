package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns role tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		List(),
		Get(),
		GetMembers(),
		Create(),
		Update(),
		Delete(),
		Grant(),
		Revoke(),
	}
}
