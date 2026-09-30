package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// Search returns the audit-event-search tool definition.
//
// Filters live in a nested `search` object; top-level inputs cover paging
// and sort.
func Search() registry.Tool {
	description := "Search PrivX audit events by keywords, user, host, connection, session, or time window. " +
		"Put filters in `search` (AND across fields). To search by event code or event name, put it in `search.keywords` " +
		"(use audit-event-codes to look up codes and names). Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer over audit-event-list when filtering. " +
		common.PresentationGuidance

	searchProps := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Free-text across audit-event fields. Include an event code or event name here to filter (see audit-event-codes).",
		}).
		Set("user_id", map[string]any{
			"type":        "string",
			"description": "Filter by PrivX user ID.",
		}).
		Set("connection_id", map[string]any{
			"type":        "string",
			"description": "Filter by connection ID.",
		}).
		Set("host_id", map[string]any{
			"type":        "string",
			"description": "Filter by host ID.",
		}).
		Set("source_id", map[string]any{
			"type":        "string",
			"description": "Filter by source ID.",
		}).
		Set("session_id", map[string]any{
			"type":        "string",
			"description": "Filter by session ID.",
		}).
		Set("access_group_id", map[string]any{
			"type":        "string",
			"description": "Filter by access group ID.",
		}).
		Set("start_time", map[string]any{
			"type":        "string",
			"description": "Inclusive start of the event time window (RFC3339).",
		}).
		Set("end_time", map[string]any{
			"type":        "string",
			"description": "Inclusive end of the event time window (RFC3339).",
		})

	searchObject := registry.NewOrderedMap().
		Set("type", "object").
		Set("description", "Optional PrivX AuditEventSearch fields (snake_case).").
		Set("properties", searchProps).
		Set("additionalProperties", false)

	properties := registry.NewOrderedMap().
		Set("search", searchObject).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Page size. Default %d.", common.AuditEventsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Record offset (not page number). Next call: nextOffset from the previous response.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "audit-event-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchAuditEventsHandler,
	}
}

func searchAuditEventsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.AuditEventsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	search, err := buildAuditEventSearch(params["search"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid search body: %v", err)), nil
	}

	client := monitor.New(authCtx.Connector)

	result, err := client.SearchAuditEvents(search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search audit events: %v", err)), nil
	}

	return common.JSONPage(paging, result.Items, result.Count, len(result.Items), common.WithNextOffset()), nil
}

// buildAuditEventSearch converts the nested `search` parameter (a
// map[string]any from the MCP client) into an AuditEventSearch by
// round-tripping through JSON. Unknown fields are dropped; only provided
// API fields are sent.
func buildAuditEventSearch(raw any) (*monitor.AuditEventSearch, error) {
	return common.UnmarshalSearch[monitor.AuditEventSearch](raw, nil)
}
