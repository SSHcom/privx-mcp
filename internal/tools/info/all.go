// Package info provides the mcp-info tool: selective session, instance, context,
// and example-resource information for LLM clients.
package info

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns info tools for registration.
func All(snapshot InstanceSnapshot) []registry.Tool {
	return []registry.Tool{Info(snapshot)}
}
