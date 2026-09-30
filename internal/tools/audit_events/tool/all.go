package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns audit-event tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		Codes(),
		List(),
		Search(),
	}
}
