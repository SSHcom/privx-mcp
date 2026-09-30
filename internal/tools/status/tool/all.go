package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns status tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		Components(),
		Instance(),
		MonitorService(),
	}
}
