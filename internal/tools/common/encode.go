package common

import (
	"encoding/json"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

// JSONResult marshals v as a successful tool payload. Encoding failures
// become a tool error result so callers never return an empty body.
func JSONResult(v any) *registry.ToolResult {
	out, err := json.Marshal(v)
	if err != nil {
		return registry.ErrorResult("failed to encode response")
	}

	return registry.TextResult(string(out))
}
