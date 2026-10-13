package tool

import (
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func managedAccountIDSchema() *registry.OrderedMap {
	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain that owns the managed account.",
		}).
		Set("account_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the managed account.",
		})

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "account_id"}).
		Set("additionalProperties", false)
}

func managedAccountIDs(params map[string]any) (string, string, *registry.ToolResult) {
	domainID := utils.StringFromMap(params, "id")
	if domainID == "" {
		return "", "", registry.ErrorResult("validation error: missing required field: id")
	}

	accountID := utils.StringFromMap(params, "account_id")
	if accountID == "" {
		return "", "", registry.ErrorResult("validation error: missing required field: account_id")
	}

	return domainID, accountID, nil
}
