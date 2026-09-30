package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the api-target-delete tool definition.
func Delete() registry.Tool {
	description := "Delete a PrivX API target by id. " +
		"Fetch with api-target-get first and obtain explicit user confirmation using name and authorized endpoints. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the API target to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "api-target-delete",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     deleteAPITargetHandler,
	}
}

func deleteAPITargetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	targetID := utils.StringFromMap(params, "id")
	if targetID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := apiproxy.New(authCtx.Connector)

	// Verify the target exists before attempting anything destructive.
	if _, err := client.GetApiTarget(targetID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch API target: %v", err)), nil
	}

	if err := client.DeleteApiTarget(targetID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete API target: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": targetID, "deleted": true}), nil
}
