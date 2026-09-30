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

// Grant returns the grant-role tool definition.
func Grant() registry.Tool {
	description := "Grant a PrivX role to a user. Supports permanent grants (no dates), " +
		"floating grants (floating_length in seconds), and restricted grants (valid_from/valid_until in RFC3339). " +
		"Time format examples: \"2025-01-15T09:00:00Z\", \"2025-06-30T17:00:00+02:00\". " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("user_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the user to grant the role to.",
		}).
		Set("role_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the role to grant.",
		}).
		Set("grant_type", map[string]any{
			"type":        "string",
			"enum":        []string{"permanent", "floating", "restricted"},
			"description": "Grant type. Defaults to permanent if omitted.",
		}).
		Set("valid_from", map[string]any{
			"type":        "string",
			"description": "Start time for restricted grants in RFC3339 format (e.g. \"2025-01-15T09:00:00Z\").",
		}).
		Set("valid_until", map[string]any{
			"type":        "string",
			"description": "End time for restricted grants in RFC3339 format (e.g. \"2025-06-30T17:00:00Z\").",
		}).
		Set("floating_length", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Duration in hours for floating grants.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"user_id", "role_id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "role-grant",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     grantRoleHandler,
	}
}

func grantRoleHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
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

	// Verify the role exists.
	role, err := client.GetRole(roleID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch role: %v", err)), nil
	}

	// Build the new role grant.
	newRole := rolestore.Role{
		ID:       role.ID,
		Name:     role.Name,
		Explicit: true,
	}

	grantType := utils.StringFromMap(params, "grant_type")
	if grantType == "" {
		grantType = "permanent"
	}
	// PrivX requires uppercase grant types.
	switch grantType {
	case "permanent", "PERMANENT":
		newRole.GrantType = "PERMANENT"
	case "floating", "FLOATING":
		newRole.GrantType = "FLOATING"

		floatingLength, err := utils.IntFromMap(params, "floating_length", 0)
		if err != nil {
			return registry.ErrorResult(fmt.Sprintf("validation error: %v", err)), nil
		}

		if floatingLength < 1 {
			return registry.ErrorResult("validation error: floating_length is required and must be >= 1 for floating grants (value is in hours)"), nil
		}

		newRole.FloatingLength = int64(floatingLength)
	case "restricted", "RESTRICTED", "time_restricted", "TIME_RESTRICTED":
		newRole.GrantType = "TIME_RESTRICTED"
		validFrom := utils.StringFromMap(params, "valid_from")

		validUntil := utils.StringFromMap(params, "valid_until")
		if validFrom == "" || validUntil == "" {
			return registry.ErrorResult("validation error: valid_from and valid_until are required for restricted grants"), nil
		}

		newRole.GrantValidityPeriods = []rolestore.ValidityPeriod{
			{GrantStart: validFrom, GrantEnd: validUntil},
		}
	default:
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid grant_type %q; must be permanent, floating, or restricted", grantType)), nil
	}

	// GET current roles, append new one, PUT all back.
	currentRoles, err := client.GetUserRoles(userID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch user roles: %v", err)), nil
	}

	// Check if role is already granted.
	for _, r := range currentRoles.Items {
		if r.ID == roleID {
			return registry.ErrorResult(fmt.Sprintf("role %q is already granted to user %s", role.Name, userID)), nil
		}
	}

	if err := client.UpdateUserRoles(userID, append(currentRoles.Items, newRole)); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to grant role: %v", err)), nil
	}

	return common.JSONResult(map[string]any{
		"user_id": userID,
		"role_id": roleID,
		"granted": true,
	}), nil
}
