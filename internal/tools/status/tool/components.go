package tool

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/status"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Components returns the status-components tool definition.
func Components() registry.Tool {
	description := "Get PrivX component status for all hosts, or one host when hostname is set. " +
		"Default fields are component_name, component_type, status.status, and status.start_time. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("hostname", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "When set, fetch status for this host only. Otherwise return components for every host.",
		}).
		Set("fields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional dotted field paths to return on top of the defaults " +
				"(component_name, component_type, status.status, status.start_time). " +
				"Unknown paths are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return component objects without field projection. WARNING: this can return a very large payload (nested status, zdu, status_details) and significantly increase token usage in the MCP client response.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "status-components",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     componentsStatusHandler,
	}
}

func componentsStatusHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	hostname := utils.StringFromMap(params, "hostname")
	fields := utils.MergeUnique(status.DefaultComponentFields(), utils.CSVFromMap(params, "fields"))
	raw := utils.BoolFromMap(params, "raw")

	client := monitor.New(authCtx.Connector)

	var (
		payload *json.RawMessage
		err     error
	)
	if hostname != "" {
		payload, err = client.GetComponentStatus(hostname)
	} else {
		payload, err = client.GetComponentsStatus()
	}

	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch component status: %v", err)), nil
	}

	decoded, err := status.DecodeJSON(payload)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to decode component status: %v", err)), nil
	}

	return common.JSONResult(status.FormatComponents(decoded, hostname, raw, fields)), nil
}
