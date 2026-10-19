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

// AccountSearch returns the target-domain-account-search tool definition.
//
// Filters live in a nested `search` object. An omitted state searches
// UNMANAGED accounts, which are the ones that can later be made managed.
func AccountSearch() registry.Tool {
	description := "Search directory accounts scanned into a PrivX target domain. " +
		"Put filters in `search`. Omitting search.state searches UNMANAGED accounts (not managed by PrivX). " +
		`Other states: "NEW", "MANAGED", "REMOVED". ` +
		"Sorted by username DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		"Default fields are id, username, full_name, email, state, and ignored. " +
		"The id identifies an account to make managed later. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	searchProps := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Free-text across scanned-account fields.",
		}).
		Set("state", map[string]any{
			"type":        "string",
			"description": `Account state. Omitted searches "UNMANAGED". Also "NEW", "MANAGED", "REMOVED".`,
		}).
		Set("ignored", map[string]any{
			"type":        "boolean",
			"description": "When set, keep only accounts with this ignored flag.",
		}).
		Set("created_after", map[string]any{
			"type":        "string",
			"format":      "date-time",
			"description": "Include accounts created at or after this RFC3339 timestamp.",
		}).
		Set("created_before", map[string]any{
			"type":        "string",
			"format":      "date-time",
			"description": "Include accounts created at or before this RFC3339 timestamp.",
		}).
		Set("updated_after", map[string]any{
			"type":        "string",
			"format":      "date-time",
			"description": "Include accounts updated at or after this RFC3339 timestamp.",
		}).
		Set("updated_before", map[string]any{
			"type":        "string",
			"format":      "date-time",
			"description": "Include accounts updated at or before this RFC3339 timestamp.",
		})

	searchObject := registry.NewOrderedMap().
		Set("type", "object").
		Set("description", "Optional PrivX scanned-account search fields (snake_case).").
		Set("properties", searchProps).
		Set("additionalProperties", false)

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain whose scanned accounts to search.",
		}).
		Set("search", searchObject).
		Set("fields", map[string]any{
			"type": "string",
			"description": "Comma-separated list of additional scanned-account fields to return on top of the defaults " +
				"(id, username, full_name, email, state, ignored). " +
				"target_domain returns id, name, and deleted. " +
				"Unknown field names are ignored. Ignored when raw is true.",
		}).
		Set("raw", map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Return scanned-account objects without field projection. WARNING: this can return a very large payload and significantly increase token usage in the MCP client response.",
		}).
		Set("limit", common.LimitSchema(common.TargetDomainsListLimit, common.TargetDomainsListMax, "")).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first account to include in the page.",
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
		Name:        "target-domain-account-search",
		Description: description,
		Writes:      false,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     searchTargetDomainAccountsHandler,
	}
}

func searchTargetDomainAccountsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.TargetDomainsListLimit, common.TargetDomainsListMax)
	if errResult != nil {
		return errResult, nil
	}

	// The managed-accounts endpoint rejects sortkey=created with 400. This
	// search uses the same account sort keys.
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

	search, err := buildScannedAccountsSearch(params["search"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid search body: %v", err)), nil
	}

	proj := target_domains.ScannedAccountProjectionFromParams(params)
	raw := utils.BoolFromMap(params, "raw")

	client := secretsmanager.New(authCtx.Connector)

	result, err := client.SearchTargetDomainAccounts(domainID, *search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search target domain accounts: %v", err)), nil
	}

	items := target_domains.FormatScannedAccountItems(result.Items, raw, proj)

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}

// buildScannedAccountsSearch converts the nested `search` parameter into a
// ScannedAccountsSearch. Unknown fields are dropped. An empty state becomes
// UNMANAGED so a call without filters lists accounts that are not managed.
func buildScannedAccountsSearch(raw any) (*secretsmanager.ScannedAccountsSearch, error) {
	search, err := common.UnmarshalSearch[secretsmanager.ScannedAccountsSearch](raw, nil)
	if err != nil {
		return nil, err
	}

	if search.State == "" {
		search.State = "UNMANAGED"
	}

	return search, nil
}
