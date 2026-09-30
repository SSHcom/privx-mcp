package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/network_targets"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Search returns the network-target-search tool definition.
//
// Filters live in a nested `search` object; top-level inputs cover paging,
// sort, projection, and raw.
func Search() registry.Tool {
	description := "Search PrivX network targets by keywords, tags, or filter expression. " +
		"Put filters in `search` (AND across fields). " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer over network-target-list when filtering. " +
		common.PresentationGuidance

	searchProps := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Free-text across network-target fields.",
		}).
		Set("tags", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Tags (OR).",
		}).
		Set("filter", map[string]any{
			"type":        "string",
			"description": "Raw PrivX filter expression when structured fields are insufficient.",
		})

	searchObject := registry.NewOrderedMap().
		Set("type", "object").
		Set("description", "Optional PrivX NetworkTargetSearch fields (snake_case).").
		Set("properties", searchProps).
		Set("additionalProperties", false)

	properties := registry.NewOrderedMap().
		Set("search", searchObject).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Page size. Default %d.", common.NetworkTargetsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Record offset (not page number). Next call: nextOffset from the previous response.",
		}).
		Set("sortKey", common.SortKeySchemaWithExamples(`"name", "updated"`)).
		Set("sortDir", common.SortDirSchema()).
		Set("fields", map[string]any{"type": "string", "description": "Extra root fields CSV beyond defaults (id, name, dst, roles, tags, comment, integration_type, disabled, exclusive_access). Ignored if raw."}).
		Set("roleFields", map[string]any{"type": "string", "description": "Extra role fields CSV beyond defaults (id, name). Ignored if raw."}).
		Set("raw", map[string]any{"type": "boolean", "default": false, "description": "Skip field projection. Large payloads."})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "network-target-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchNetworkTargetsHandler,
	}
}

func searchNetworkTargetsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.NetworkTargetsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	raw := utils.BoolFromMap(params, "raw")

	search, err := buildNetworkTargetSearch(params["search"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid search body: %v", err)), nil
	}

	client := networkaccessmanager.New(authCtx.Connector)

	result, err := client.SearchNetworkTargets(*search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search network targets: %v", err)), nil
	}

	fetched := len(result.Items)
	items := network_targets.FormatNetworkTargetItems(result.Items, raw, network_targets.ProjectionFromParams(params))

	return common.JSONPage(paging, items, result.Count, fetched, common.WithNextOffset()), nil
}

// buildNetworkTargetSearch converts the nested `search` parameter (a
// map[string]any from the MCP client) into a NetworkTargetSearch by
// round-tripping through JSON. Unknown fields are dropped; only provided
// API fields are sent.
func buildNetworkTargetSearch(raw any) (*networkaccessmanager.NetworkTargetSearch, error) {
	return common.UnmarshalSearch[networkaccessmanager.NetworkTargetSearch](raw, nil)
}
