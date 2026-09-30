package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/hosts"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// List returns the host-list tool definition.
func List() registry.Tool {
	description := "List PrivX hosts with pagination. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer host-search when filtering. " +
		"For connection link creation guidance, see mcp-info -> context: connection. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("fields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional root host fields to return on top of the defaults (id, common_name, addresses, disabled, services, principals). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("serviceFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional service fields to return on top of the defaults (service, address, status). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("principalFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional principal fields to return on top of the defaults (principal, roles). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return host objects without field projection. Sensitive fields are omitted. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of hosts to return. Defaults to %d.", common.HostsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first host to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "host-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listHostsHandler,
	}
}

func listHostsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.HostsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	proj := hosts.ProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := hoststore.New(authCtx.Connector)

	result, err := client.GetHosts(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch hosts: %v", err)), nil
	}

	items := hosts.FormatHostItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
