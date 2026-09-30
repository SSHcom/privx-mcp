package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// List returns the whitelist-list tool definition.
func List() registry.Tool {
	description := "List all PrivX SSH command whitelists with pagination. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of whitelists to return. Defaults to %d.", common.WhitelistsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first whitelist to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "whitelist-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listHandler,
	}
}

func listHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.WhitelistsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	client := hoststore.New(authCtx.Connector)

	result, err := client.GetWhitelists(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch whitelists: %v", err)), nil
	}

	return common.JSONPage(paging, result.Items, result.Count, len(result.Items)), nil
}
