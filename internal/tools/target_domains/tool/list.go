package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/target_domains"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// List returns the target-domain-list tool definition.
func List() registry.Tool {
	description := "List PrivX target domains with pagination. " +
		"Sorted by name DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("fields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional root target-domain fields to return on top of the defaults " +
				"(id, name, domain_name, enabled, periodic_scan, scan_status, last_scanned, auto_onboarding, comment). " +
				"Include endpoints to project that array with the endpoint field defaults. " +
				"Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("endpointFields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional endpoint fields to return on top of the defaults " +
				"(type, scan_priority, rotation_priority, ldap_address, ldap_port, ldap_base_dn, entra_tenant_id) " +
				"when endpoints is included. Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return target-domain objects without field projection. Credential fields are omitted. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Maximum number of target domains to return. Defaults to %d.", common.TargetDomainsListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first target domain to include in the page.",
		}).
		Set("sortKey", map[string]any{
			"type":        "string",
			"enum":        []string{"id", "name"},
			"default":     "name",
			"description": `Sort key. Defaults to "name".`,
		}).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "target-domain-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listTargetDomainsHandler,
	}
}

func listTargetDomainsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.TargetDomainsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	sortKey := utils.StringFromMap(params, "sortKey")
	if sortKey == "" {
		paging.SortKey = "name"
	} else if sortKey != "id" && sortKey != "name" {
		return registry.ErrorResult("validation error: sortKey must be id or name"), nil
	}

	proj := target_domains.ProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := secretsmanager.New(authCtx.Connector)

	result, err := client.GetTargetDomains(paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch target domains: %v", err)), nil
	}

	items := target_domains.FormatTargetDomainItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
