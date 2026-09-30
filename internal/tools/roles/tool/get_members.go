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

// GetMembers returns the get-role-members tool definition.
func GetMembers() registry.Tool {
	description := "Get users assigned to a PrivX role. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("role_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the role whose members to fetch.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of members to return. Defaults to %d.", common.RolesListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first member to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"role_id"})

	return registry.Tool{
		Name:        "role-members",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getRoleMembersHandler,
	}
}

func getRoleMembersHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	roleID := utils.StringFromMap(params, "role_id")
	if roleID == "" {
		return registry.ErrorResult("validation error: missing required field: role_id"), nil
	}

	paging, errResult := common.ParsePaging(params, common.RolesListLimit)
	if errResult != nil {
		return errResult, nil
	}

	client := rolestore.New(authCtx.Connector)

	result, err := client.GetRoleMembers(roleID, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch role members: %v", err)), nil
	}

	items := users.FormatUserItems(result.Items, true, users.Projection{})

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
