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

// List returns the user-list tool definition.
func List() registry.Tool {
	description := "List PrivX users (local and directory) with pagination. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer user-search when filtering. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("fields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional root user fields to return on top of the defaults (id, principal, source, source_type, email, full_name, roles). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("roleFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional role fields to return on top of the defaults (id, name) when roles is a non-null array. Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return user objects without field projection. Sensitive fields are omitted. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of users to return. Defaults to %d.", common.UsersListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first user to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "user-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listUsersHandler,
	}
}

func listUsersHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.UsersListLimit)
	if errResult != nil {
		return errResult, nil
	}

	proj := users.ProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := rolestore.New(authCtx.Connector)

	result, err := client.SearchUsers(rolestore.UserSearch{}, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch users: %v", err)), nil
	}

	items := users.FormatUserItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
