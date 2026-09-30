package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Search returns the whitelist-search tool definition.
func Search() registry.Tool {
	description := "Search PrivX SSH command whitelists by keywords. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Free-text search across whitelist fields.",
		}).
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
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "whitelist-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchHandler,
	}
}

func searchHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.WhitelistsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	search := hoststore.WhitelistSearch{
		Keywords: utils.StringFromMap(params, "keywords"),
	}

	client := hoststore.New(authCtx.Connector)

	result, err := client.SearchWhitelists(search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search whitelists: %v", err)), nil
	}

	return common.JSONPage(paging, result.Items, result.Count, len(result.Items), common.WithNextOffset()), nil
}
