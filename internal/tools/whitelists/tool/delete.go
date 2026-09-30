package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the whitelist-delete tool definition.
func Delete() registry.Tool {
	description := "Delete a PrivX SSH command whitelist by ID. " +
		"Warning: deleting a whitelist referenced by host command_restrictions will break those restrictions. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the whitelist to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "whitelist-delete",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     deleteHandler,
	}
}

func deleteHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	whitelistID := utils.StringFromMap(params, "id")
	if whitelistID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := hoststore.New(authCtx.Connector)
	if err := client.DeleteWhitelist(whitelistID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete whitelist: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": whitelistID, "deleted": true}), nil
}
