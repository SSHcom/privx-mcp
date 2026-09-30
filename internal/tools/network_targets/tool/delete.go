package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the network-target-delete tool definition.
func Delete() registry.Tool {
	description := "Delete a PrivX network target by id. " +
		"Fetch with network-target-get first and obtain explicit user confirmation using name and destinations. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the network target to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "network-target-delete",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     deleteNetworkTargetHandler,
	}
}

func deleteNetworkTargetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	targetID := utils.StringFromMap(params, "id")
	if targetID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := networkaccessmanager.New(authCtx.Connector)

	// Verify the target exists before attempting anything destructive.
	if _, err := client.GetNetworkTarget(targetID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch network target: %v", err)), nil
	}

	if err := client.DeleteNetworkTarget(targetID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete network target: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": targetID, "deleted": true}), nil
}
