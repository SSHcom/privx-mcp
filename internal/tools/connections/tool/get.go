package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/connections"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the connection-get tool definition.
func Get() registry.Tool {
	description := "Get a single PrivX connection by ID. " +
		"Returns connection details including user, target host, status, and timing. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the connection to fetch.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"description": "Return full unfiltered connection data. Default: false (compact view).",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "connection-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getConnectionHandler,
	}
}

func getConnectionHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	connID := utils.StringFromMap(params, "id")
	if connID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	raw := utils.BoolFromMap(params, "raw")

	client := connectionmanager.New(authCtx.Connector)

	conn, err := client.GetConnection(connID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch connection: %v", err)), nil
	}

	return common.JSONResult(connections.FormatSingleConnection(conn, raw)), nil
}
