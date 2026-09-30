package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns SSH command whitelist tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		List(),
		Get(),
		Search(),
		Create(),
		Update(),
		Delete(),
		Evaluate(),
	}
}
