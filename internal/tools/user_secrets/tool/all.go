package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns user-secret tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		List(),
		Get(),
		Create(),
		Update(),
		Delete(),
	}
}
