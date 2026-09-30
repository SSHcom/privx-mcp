package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/api_targets"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// List returns the api-target-list tool definition.
func List() registry.Tool {
	description := "List PrivX API targets with pagination. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("fields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional root api-target fields to return on top of the defaults " +
				"(id, name, access_group_id, roles, authorized_endpoints). " +
				"Include unauthorized_endpoints to project that array with the same endpoint field defaults. " +
				"Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("roleFields", map[string]any{
			"type":        "string",
			"description": "Comma-separated list of additional role fields to return on top of the defaults (id, name) when roles is present. Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("endpointFields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional endpoint fields to return on top of the defaults " +
				"(host, nat_target_host, allow_unauthenticated, protocols, methods, paths) for authorized_endpoints " +
				"and unauthorized_endpoints (when requested). Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return api-target objects without field projection. Sensitive fields are omitted. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of API targets to return. Defaults to %d.", common.APITargetsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first API target to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "api-target-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listAPITargetsHandler,
	}
}

func listAPITargetsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.APITargetsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	proj := api_targets.ProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := apiproxy.New(authCtx.Connector)

	result, err := client.GetApiTargets(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch API targets: %v", err)), nil
	}

	items := api_targets.FormatAPITargetItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
