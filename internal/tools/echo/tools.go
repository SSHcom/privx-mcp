package devtools

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// TestTools returns testing tools for registration.
func TestTools() []registry.Tool {
	return []registry.Tool{
		echoTool(),
	}
}
