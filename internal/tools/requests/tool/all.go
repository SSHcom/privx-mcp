package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns workflow access-request tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		Create(),
		Delete(),
		Get(),
		List(),
		Revoke(),
		Search(),
		SetDecision(),
	}
}
