package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the access-group-delete tool definition.
func Delete() registry.Tool {
	description := "Delete a PrivX access group by ID. " +
		"Warning: deleting an access group may orphan hosts, roles, and targets assigned to it. " +
		"The default access group cannot be deleted. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the access group to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "access-group-delete",
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

	accessGroupID := utils.StringFromMap(params, "id")
	if accessGroupID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := authorizer.New(authCtx.Connector)
	if err := client.DeleteAccessGroup(accessGroupID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete access group: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": accessGroupID, "deleted": true}), nil
}
