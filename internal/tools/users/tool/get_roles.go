package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/users"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// GetRoles returns the user-get-roles tool definition.
func GetRoles() registry.Tool {
	description := "Fetch PrivX roles assigned to a user by user id. " +
		"Defaults return id, name, and context.enabled. " +
		"If the end-user does not have a user id, use user-search first to resolve it. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the user whose roles to fetch.",
		}).
		Set("sourceRules", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Include the full source_rules object on each role. Ignored when raw is true.",
		}).
		Set("contextFields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional context fields to return on top of the default (enabled). " +
				"Exact field names as on the role context object (e.g. validity, start_time, end_time, timezone, block_role). " +
				"Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return role objects without field projection, overriding sourceRules and contextFields. Sensitive fields are omitted. WARNING: this can return a large payload and increase token usage.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "user-get-roles",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getUserRolesHandler,
	}
}

func getUserRolesHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	userID := utils.StringFromMap(params, "id")
	if userID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	includeSourceRules := utils.BoolFromMap(params, "sourceRules")
	contextFields := utils.MergeUnique(users.DefaultUserRoleContextFields, utils.CSVFromMap(params, "contextFields"))
	raw := utils.BoolFromMap(params, "raw")

	client := rolestore.New(authCtx.Connector)

	roles, err := client.GetUserRoles(userID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch user roles: %v", err)), nil
	}

	items := users.FormatUserRoleItems(roles.Items, raw, includeSourceRules, contextFields)

	return common.JSONResult(map[string]any{
		"count": roles.Count,
		"items": items,
	}), nil
}
