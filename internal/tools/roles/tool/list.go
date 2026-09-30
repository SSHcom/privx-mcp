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

// List returns the role-list tool definition.
func List() registry.Tool {
	description := "List all PrivX roles with pagination. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of roles to return. Defaults to %d.", common.RolesListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first role to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "role-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listRolesHandler,
	}
}

func listRolesHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.RolesListLimit)
	if errResult != nil {
		return errResult, nil
	}

	client := rolestore.New(authCtx.Connector)

	result, err := client.GetRoles(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch roles: %v", err)), nil
	}

	items := make([]map[string]any, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, users.RedactSensitiveRoleFields(utils.ToJSONMap(item)))
	}

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
