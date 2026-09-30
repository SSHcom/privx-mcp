package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/connections"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// List returns the connections-list tool definition.
func List() registry.Tool {
	description := "List PrivX connections with pagination. " +
		"Sorted by connected time descending by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of connections to return. Defaults to %d.", common.ConnectionsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first connection to include in the page.",
		}).
		Set("sortKey", map[string]any{
			"type":        "string",
			"description": `Sort key (e.g. "connected", "disconnected", "type"). Defaults to "connected".`,
		}).
		Set("sortDir", common.SortDirSchema()).
		Set("raw", map[string]any{
			"type":        "boolean",
			"description": "Return full unfiltered connection data. Default: false (compact view).",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "connection-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listConnectionsHandler,
	}
}

func listConnectionsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := parseConnectionsPaging(params)
	if errResult != nil {
		return errResult, nil
	}

	raw := utils.BoolFromMap(params, "raw")

	client := connectionmanager.New(authCtx.Connector)

	result, err := client.GetConnections(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch connections: %v", err)), nil
	}

	return common.JSONPage(
		paging,
		connections.FormatConnectionItems(result.Items, raw),
		result.Count,
		len(result.Items),
	), nil
}

// parseConnectionsPaging extracts paging params with "connected" as the default sort key.
func parseConnectionsPaging(params map[string]any) (common.Paging, *registry.ToolResult) {
	paging, errResult := common.ParsePaging(params, common.ConnectionsListLimit)
	if errResult != nil {
		return paging, errResult
	}
	// Override default sort key from "created" to "connected" for connections.
	if paging.SortKey == common.DefaultSortKey {
		sortKey := ""
		if params != nil {
			sortKey, _ = params["sortKey"].(string)
		}

		if sortKey == "" {
			paging.SortKey = "connected"
		}
	}

	return paging, nil
}
