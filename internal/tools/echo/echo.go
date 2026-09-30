// Package devtools provides testing-only MCP tools.
package devtools

import (
	"context"
	"fmt"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func echoTool() registry.Tool {
	return registry.Tool{
		Name:        "echo",
		Description: "Returns the input message back to the caller. Hello-world tool for testing; any authenticated MCP caller can use it. " + common.PresentationGuidance,
		Writes:      false,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"message": map[string]any{
					"type":        "string",
					"description": "Any text to echo back.",
					"minLength":   1,
				},
			},
			"required": []string{"message"},
		},
		Handler: echoHandler,
	}
}

func echoHandler(_ context.Context, params map[string]any) (*registry.ToolResult, error) {
	message, _ := params["message"].(string)
	if message == "" {
		return registry.ErrorResult("validation error: message is required"), nil
	}

	return common.JSONResult(map[string]string{"echo": fmt.Sprintf("dummy: %s", message)}), nil
}
