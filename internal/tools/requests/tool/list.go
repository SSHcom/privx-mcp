package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/requests"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// List returns the request-list tool definition.
func List() registry.Tool {
	description := "List PrivX access requests with pagination. " +
		"`filter` is ALL|ACTIVE_APPROVALS|APPROVALS|REQUESTS; defaults to ALL. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer request-search when filtering. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("filter", requestFilterSchema()).
		Set("fields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional root request fields to return on top of the defaults (id, requester, requested_role, steps). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("stepFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional step fields to return on top of the defaults (id, name, approvers) when steps is a non-null array. Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("approverFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional approver fields to return on top of the defaults (id, decision) when approvers is a non-null array. Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return access-request objects without field projection. WARNING: this can return a large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of requests to return. Defaults to %d.", common.RequestsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first request to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "request-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listRequestsHandler,
	}
}

func listRequestsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.RequestsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	filter, err := requestFilterFromMap(params)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: %v", err)), nil
	}

	proj := requests.ProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	opts := append(paging.FilterOptions(), filters.Filter(filter))
	client := workflow.New(authCtx.Connector)

	result, err := client.GetRequests(opts...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch access requests: %v", err)), nil
	}

	items := requests.FormatRequestItems(result.Items, raw, proj)

	return common.JSONPage(
		paging,
		items,
		result.Count,
		len(result.Items),
		common.WithExtra("filter", filter),
	), nil
}
