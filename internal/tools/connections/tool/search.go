package tool

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/connections"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

const (
	connectionSearchDefaultWindow = 7 * 24 * time.Hour
	connectionSearchMaxWindow     = 30 * 24 * time.Hour
)

// Search returns the connections-search tool definition.
func Search() registry.Tool {
	description := "Search PrivX connections with filters. " +
		"Supports filtering by status (CONNECTED, DISCONNECTED, TERMINATED), " +
		"type (SSH, RDP, VNC, WEB, DB), user, host, time range, and keywords. " +
		"connected_start and connected_end default to the last 7 days. " +
		"The window can be any dates and cannot exceed 30 days. " +
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
			"type": "string",
			"description": "Inclusive RFC3339 start of the connected window. " +
				"Defaults to 7 days before connected_end, or to 7 days ago when both bounds are omitted. " +
				"The window can be any dates and cannot exceed 30 days.",
		}).
		Set("connected_end", map[string]any{
			"type": "string",
			"description": "Inclusive RFC3339 end of the connected window. " +
				"Defaults to 7 days after connected_start, or to now when both bounds are omitted. " +
				"The window can be any dates and cannot exceed 30 days.",
		}).
		Set("limit", common.LimitSchema(common.ConnectionsListLimit, common.ConnectionsListMax, "")).
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

	connStart, connEnd, errResult := resolveConnectedWindow(
		utils.StringFromMap(params, "connected_start"),
		utils.StringFromMap(params, "connected_end"),
		time.Now(),
	)
	if errResult != nil {
		return nil, errResult
	}

	search.Connected = &connectionmanager.TimestampSearch{
		Start: connStart,
		End:   connEnd,
	}

	return search, nil
}

// resolveConnectedWindow fills a missing connected window with the last 7 days
// and rejects a span longer than 30 days. A single bound anchors a 7-day window.
func resolveConnectedWindow(startRaw, endRaw string, now time.Time) (string, string, *registry.ToolResult) {
	startRaw = strings.TrimSpace(startRaw)
	endRaw = strings.TrimSpace(endRaw)

	switch {
	case startRaw == "" && endRaw == "":
		end := now.UTC()
		start := end.Add(-connectionSearchDefaultWindow)

		return start.Format(time.RFC3339), end.Format(time.RFC3339), nil
	case startRaw != "" && endRaw == "":
		start, errResult := parseConnectedTime("connected_start", startRaw)
		if errResult != nil {
			return "", "", errResult
		}

		return startRaw, start.Add(connectionSearchDefaultWindow).UTC().Format(time.RFC3339), nil
	case startRaw == "" && endRaw != "":
		end, errResult := parseConnectedTime("connected_end", endRaw)
		if errResult != nil {
			return "", "", errResult
		}

		return end.Add(-connectionSearchDefaultWindow).UTC().Format(time.RFC3339), endRaw, nil
	}

	start, errResult := parseConnectedTime("connected_start", startRaw)
	if errResult != nil {
		return "", "", errResult
	}

	end, errResult := parseConnectedTime("connected_end", endRaw)
	if errResult != nil {
		return "", "", errResult
	}

	if end.Before(start) {
		return "", "", registry.ErrorResult("validation error: connected_end must not be before connected_start")
	}

	if end.Sub(start) > connectionSearchMaxWindow {
		return "", "", registry.ErrorResult("validation error: connected range cannot exceed 30 days")
	}

	return startRaw, endRaw, nil
}

func parseConnectedTime(field, value string) (time.Time, *registry.ToolResult) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, registry.ErrorResult(fmt.Sprintf("validation error: %s must be RFC3339", field))
	}

	return parsed, nil
}
