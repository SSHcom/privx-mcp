package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the delete-role tool definition.
func Delete() registry.Tool {
	description := "Delete a PrivX role by id. " +
		"Checks for existing role members and warns before deletion. " +
		"Note: principal public keys associated with this role will not be automatically removed from target host accounts. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the role to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "role-delete",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     deleteRoleHandler,
	}
}

func deleteRoleHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	roleID := utils.StringFromMap(params, "id")
	if roleID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := rolestore.New(authCtx.Connector)

	// Verify the role exists.
	role, err := client.GetRole(roleID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch role: %v", err)), nil
	}

	// Check for existing members and warn.
	members, err := client.GetRoleMembers(roleID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to check role members: %v", err)), nil
	}

	if members.Count > 0 {
		return registry.ErrorResult(fmt.Sprintf(
			"refusing to delete role %q (%s): role has %d active member(s). "+
				"Remove all members before deleting, or confirm forced deletion is intended.",
			role.Name, roleID, members.Count,
		)), nil
	}

	if err := client.DeleteRole(roleID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete role: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": roleID, "deleted": true}), nil
}
