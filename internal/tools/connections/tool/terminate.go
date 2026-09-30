package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Terminate returns the connection-terminate tool definition.
func Terminate() registry.Tool {
	description := "Terminate an active PrivX connection by ID. " +
		"This forcefully ends a live session. " +
		"Only works on connections with status CONNECTED. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the connection to terminate.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "connection-terminate",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     terminateConnectionHandler,
	}
}

func terminateConnectionHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	connID := utils.StringFromMap(params, "id")
	if connID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := connectionmanager.New(authCtx.Connector)
	if err := client.TerminateConnection(connID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to terminate connection: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": connID, "terminated": true}), nil
}
