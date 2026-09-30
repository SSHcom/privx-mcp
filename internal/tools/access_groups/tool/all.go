package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns access group tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		List(),
		Get(),
		Create(),
		Update(),
		Delete(),
	}
}
