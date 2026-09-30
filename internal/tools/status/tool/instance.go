package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/status"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Instance returns the status-instance tool definition.
func Instance() registry.Tool {
	description := "Get PrivX instance status from monitor-service. " +
		"The response is an array of components; default fields are component_name, component_type, status.status, and status.start_time. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("fields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional dotted field paths to return on top of the defaults " +
				"(component_name, component_type, status.status, status.start_time). " +
				"Unknown paths are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return the component objects without field projection. WARNING: this can return a large payload (nested status, zdu, status_details) and significantly increase token usage in the MCP client response.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "status-instance",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     instanceStatusHandler,
	}
}

func instanceStatusHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	fields := utils.MergeUnique(status.DefaultComponentFields(), utils.CSVFromMap(params, "fields"))
	raw := utils.BoolFromMap(params, "raw")

	client := monitor.New(authCtx.Connector)

	payload, err := client.GetInstanceStatus()
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch instance status: %v", err)), nil
	}

	decoded, err := status.DecodeJSON(payload)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to decode instance status: %v", err)), nil
	}

	return common.JSONResult(status.FormatInstance(decoded, raw, fields)), nil
}
