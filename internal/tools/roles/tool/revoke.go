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

// Revoke returns the revoke-role tool definition.
func Revoke() registry.Tool {
	description := "Revoke a PrivX role from a user. " + common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("user_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the user to revoke the role from.",
		}).
		Set("role_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the role to revoke.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"user_id", "role_id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "role-revoke",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     revokeRoleHandler,
	}
}

func revokeRoleHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	userID := utils.StringFromMap(params, "user_id")
	if userID == "" {
		return registry.ErrorResult("validation error: missing required field: user_id"), nil
	}

	roleID := utils.StringFromMap(params, "role_id")
	if roleID == "" {
		return registry.ErrorResult("validation error: missing required field: role_id"), nil
	}

	client := rolestore.New(authCtx.Connector)

	// GET current roles, remove the target, PUT all back.
	currentRoles, err := client.GetUserRoles(userID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch user roles: %v", err)), nil
	}

	found := false

	updatedRoles := make([]rolestore.Role, 0, len(currentRoles.Items))
	for _, r := range currentRoles.Items {
		if r.ID == roleID {
			found = true
			continue
		}

		updatedRoles = append(updatedRoles, r)
	}

	if !found {
		return registry.ErrorResult(fmt.Sprintf("role %s is not granted to user %s", roleID, userID)), nil
	}

	if err := client.UpdateUserRoles(userID, updatedRoles); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to revoke role: %v", err)), nil
	}

	return common.JSONResult(map[string]any{
		"user_id": userID,
		"role_id": roleID,
		"revoked": true,
	}), nil
}
