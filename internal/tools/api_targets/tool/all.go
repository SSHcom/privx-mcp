package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns api-target tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		Delete(),
		Get(),
		List(),
	}
}
