package tool

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/requests"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Search returns the request-search tool definition.
func Search() registry.Tool {
	description := "Search PrivX access requests. " +
		"Put keywords/start_time/end_time in `search`. " +
		"`filter` is a separate top-level argument (NOT inside search): ALL|ACTIVE_APPROVALS|APPROVALS|REQUESTS; defaults to ALL. " +
		"When looking for a specific user's request, always put that user's username or email in search.keywords " +
		"(with filter=ACTIVE_APPROVALS, REQUESTS, or ALL as appropriate). " +
		"Sorted by created DESC by default. " +
		"Prefer over request-list when filtering. " +
		common.PresentationGuidance

	searchProps := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type": "string",
			"description": "Free-text across access-request fields. " +
				"For a specific user's requests, include their username or email.",
		}).
		Set("start_time", map[string]any{
			"type":        "string",
			"description": "Inclusive start of the created/updated time window (RFC3339).",
		}).
		Set("end_time", map[string]any{
			"type":        "string",
			"description": "Inclusive end of the created/updated time window (RFC3339).",
		})

	searchObject := registry.NewOrderedMap().
		Set("type", "object").
		Set("description", "PrivX search body only: keywords, start_time, end_time. Do not put filter here — use top-level filter.").
		Set("properties", searchProps).
		Set("additionalProperties", false)

	properties := registry.NewOrderedMap().
		Set("search", searchObject).
		Set("filter", requestFilterSchema()).
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
		Set("sortKey", common.SortKeySchemaWithExamples(`"updated", "id"`)).
		Set("sortDir", common.SortDirSchema()).
		Set("fields", map[string]any{"type": "string", "description": "Extra root fields CSV beyond defaults (id, requester, requested_role, steps). Ignored if raw."}).
		Set("stepFields", map[string]any{"type": "string", "description": "Extra step fields CSV beyond defaults (id, name, approvers). Ignored if raw."}).
		Set("approverFields", map[string]any{"type": "string", "description": "Extra approver fields CSV beyond defaults (id, decision). Ignored if raw."}).
		Set("raw", map[string]any{"type": "boolean", "default": false, "description": "Skip field projection. Large payloads."})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "request-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchRequestsHandler,
	}
}

func searchRequestsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
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

	raw := utils.BoolFromMap(params, "raw")

	search, err := buildAccessRequestSearch(params["search"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid search body: %v", err)), nil
	}

	client := workflow.New(authCtx.Connector)

	opts := append(paging.FilterOptions(), filters.Filter(filter))

	query := url.Values{}
	for _, opt := range opts {
		opt(&query)
	}

	logging.Debug("request-search URL params", "query", query.Encode())

	result, err := client.SearchRequests(search, opts...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search access requests: %v", err)), nil
	}

	formatted := requests.FormatRequestItems(result.Items, raw, requests.ProjectionFromParams(params))

	return common.JSONPage(
		paging,
		formatted,
		result.Count,
		len(result.Items),
		common.WithNextOffset(),
		common.WithExtra("filter", filter),
	), nil
}

func buildAccessRequestSearch(raw any) (*workflow.AccessRequestSearch, error) {
	search, err := common.UnmarshalSearch[workflow.AccessRequestSearch](raw, nil)
	if err != nil {
		return nil, err
	}

	// Filter belongs in the query string, not the JSON body (PrivX API).
	search.Filter = ""
	search.Keywords = strings.TrimSpace(search.Keywords)

	return search, nil
}
