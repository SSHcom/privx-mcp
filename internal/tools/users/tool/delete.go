package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the user-delete-local tool definition.
//
// The tool description instructs callers to fetch the user with user-get and
// obtain explicit user confirmation before deleting. Server-side,
// user-delete-local verifies the local user exists via GetUser, then deletes
// it from the PrivX Local User Store.
func Delete() registry.Tool {
	description := "Delete a local PrivX user by id. " +
		"Fetch with user-get first and obtain explicit user confirmation using principal, email, and full_name. " +
		"Local users only; directory users cannot be removed here. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the local user to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-delete-local",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     deleteUserHandler,
	}
}

func deleteUserHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	userID := utils.StringFromMap(params, "id")
	if userID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := userstore.New(authCtx.Connector)
	if _, err := client.GetUser(userID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch local user: %v", err)), nil
	}

	if err := client.DeleteUser(userID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete local user: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": userID, "deleted": true}), nil
}
