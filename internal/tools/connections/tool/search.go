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

// Search returns the connections-search tool definition.
func Search() registry.Tool {
	description := "Search PrivX connections with filters. " +
		"Supports filtering by status (CONNECTED, DISCONNECTED, TERMINATED), " +
		"type (SSH, RDP, VNC, WEB, DB), user, host, time range, and keywords. " +
		"Sorted by connected time descending by default. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Free-text search across connection fields.",
		}).
		Set("status", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": `Filter by connection status (e.g. ["CONNECTED", "DISCONNECTED", "TERMINATED"]).`,
		}).
		Set("type", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": `Filter by connection type (e.g. ["SSH", "RDP", "VNC", "WEB", "DB"]).`,
		}).
		Set("user_id", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Filter by user IDs.",
		}).
		Set("target_host_id", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Filter by target host IDs.",
		}).
		Set("target_host_address", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Filter by target host addresses.",
		}).
		Set("target_host_common_name", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Filter by target host common names.",
		}).
		Set("connected_start", map[string]any{
			"type":        "string",
			"description": "Inclusive start of the connected time window (RFC3339).",
		}).
		Set("connected_end", map[string]any{
			"type":        "string",
			"description": "Inclusive end of the connected time window (RFC3339).",
		}).
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
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "connection-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchConnectionsHandler,
	}
}

func searchConnectionsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := parseConnectionsPaging(params)
	if errResult != nil {
		return errResult, nil
	}

	search, errResult := buildConnectionSearch(params)
	if errResult != nil {
		return errResult, nil
	}

	raw := utils.BoolFromMap(params, "raw")

	client := connectionmanager.New(authCtx.Connector)

	result, err := client.SearchConnections(search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search connections: %v", err)), nil
	}

	return common.JSONPage(
		paging,
		connections.FormatConnectionItems(result.Items, raw),
		result.Count,
		len(result.Items),
		common.WithNextOffset(),
	), nil
}

func buildConnectionSearch(params map[string]any) (*connectionmanager.ConnectionSearch, *registry.ToolResult) {
	search := &connectionmanager.ConnectionSearch{}

	search.KeyWords = utils.StringFromMap(params, "keywords")

	if raw, ok := params["status"]; ok {
		sl, err := utils.ToStringSlice(raw)
		if err != nil {
			return nil, registry.ErrorResult(fmt.Sprintf("validation error: status: %v", err))
		}

		search.Status = sl
	}

	if raw, ok := params["type"]; ok {
		sl, err := utils.ToStringSlice(raw)
		if err != nil {
			return nil, registry.ErrorResult(fmt.Sprintf("validation error: type: %v", err))
		}

		search.Type = sl
	}

	if raw, ok := params["user_id"]; ok {
		sl, err := utils.ToStringSlice(raw)
		if err != nil {
			return nil, registry.ErrorResult(fmt.Sprintf("validation error: user_id: %v", err))
		}

		search.UserID = sl
	}

	if raw, ok := params["target_host_id"]; ok {
		sl, err := utils.ToStringSlice(raw)
		if err != nil {
			return nil, registry.ErrorResult(fmt.Sprintf("validation error: target_host_id: %v", err))
		}

		search.TargetHost = sl
	}

	if raw, ok := params["target_host_address"]; ok {
		sl, err := utils.ToStringSlice(raw)
		if err != nil {
			return nil, registry.ErrorResult(fmt.Sprintf("validation error: target_host_address: %v", err))
		}

		search.TargetHostAddress = sl
	}

	if raw, ok := params["target_host_common_name"]; ok {
		sl, err := utils.ToStringSlice(raw)
		if err != nil {
			return nil, registry.ErrorResult(fmt.Sprintf("validation error: target_host_common_name: %v", err))
		}

		search.TargetHostCommonName = sl
	}

	connStart := utils.StringFromMap(params, "connected_start")

	connEnd := utils.StringFromMap(params, "connected_end")
	if connStart != "" || connEnd != "" {
		search.Connected = &connectionmanager.TimestampSearch{
			Start: connStart,
			End:   connEnd,
		}
	}

	return search, nil
}
