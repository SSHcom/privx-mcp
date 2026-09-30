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

// List returns the network-target-list tool definition.
func List() registry.Tool {
	description := "List PrivX network targets with pagination. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer network-target-search when filtering. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("fields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional root network-target fields to return on top of the defaults (id, name, dst, roles, tags, comment, integration_type, disabled, exclusive_access). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("roleFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional role fields to return on top of the defaults (id, name) when roles is a non-null array. Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return network-target objects without field projection. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of network targets to return. Defaults to %d.", common.NetworkTargetsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first network target to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "network-target-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listNetworkTargetsHandler,
	}
}

func listNetworkTargetsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.NetworkTargetsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	proj := network_targets.ProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := networkaccessmanager.New(authCtx.Connector)

	result, err := client.GetNetworkTargets(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch network targets: %v", err)), nil
	}

	items := network_targets.FormatNetworkTargetItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
