package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns network-target tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		Create(),
		Delete(),
		Get(),
		List(),
		Search(),
		Update(),
	}
}
