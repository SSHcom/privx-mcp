package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// List returns the audit-event-list tool definition.
func List() registry.Tool {
	description := "List PrivX audit events with pagination. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer audit-event-search when filtering. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of audit events to return. Defaults to %d.", common.AuditEventsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first audit event to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "audit-event-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listAuditEventsHandler,
	}
}

func listAuditEventsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.AuditEventsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	client := monitor.New(authCtx.Connector)

	result, err := client.GetAuditEvents(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch audit events: %v", err)), nil
	}

	return common.JSONPage(paging, result.Items, result.Count, len(result.Items)), nil
}
