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

// ManagedAccountList returns the target-domain-managed-account-list tool definition.
func ManagedAccountList() registry.Tool {
	description := "List managed accounts under a PrivX target domain with pagination. " +
		"Sorted by username DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		"Checkout passwords are omitted. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain whose managed accounts to list.",
		}).
		Set("fields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional managed-account fields to return on top of the defaults " +
				"(id, username, full_name, email, enabled, rotation_enabled, explicit_checkout, state, password_policy, comment, locked). " +
				"password_policy and target_domain return id, name, and deleted. " +
				"rotation_history returns version, rotated, trigger, and status. " +
				"checkouts returns id, user_id, expires, created, explicit_checkout, and username. " +
				"Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return managed-account objects without field projection. Checkout passwords are omitted. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", common.LimitSchema(common.TargetDomainsListLimit, common.TargetDomainsListMax, "")).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first managed account to include in the page.",
		}).
		Set("sortKey", map[string]any{
			"type":        "string",
			"enum":        []string{"id", "username", "full_name", "email"},
			"default":     "username",
			"description": `Sort key. Defaults to "username".`,
		}).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "target-domain-managed-account-list",
		Description: description,
		Writes:      false,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     listManagedAccountsHandler,
	}
}

func listManagedAccountsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.TargetDomainsListLimit, common.TargetDomainsListMax)
	if errResult != nil {
		return errResult, nil
	}

	// The managed-accounts endpoint rejects sortkey=created with 400.
	sortKey := utils.StringFromMap(params, "sortKey")
	switch sortKey {
	case "":
		paging.SortKey = "username"
	case "id", "username", "full_name", "email":
	default:
		return registry.ErrorResult("validation error: sortKey must be id, username, full_name, or email"), nil
	}

	domainID := utils.StringFromMap(params, "id")
	if domainID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	proj := target_domains.ManagedAccountProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := secretsmanager.New(authCtx.Connector)

	result, err := client.GetManagedAccounts(domainID, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch managed accounts: %v", err)), nil
	}

	items := target_domains.FormatManagedAccountItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}
