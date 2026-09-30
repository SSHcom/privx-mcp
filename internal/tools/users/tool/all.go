package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns user tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		Create(),
		Delete(),
		Get(),
		GetRoles(),
		List(),
		Search(),
		Update(),
	}
}
