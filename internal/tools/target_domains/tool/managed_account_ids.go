package tool

import (
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
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
	domainID, errResult := common.RequiredPathID(params, "id")
	if errResult != nil {
		return "", "", errResult
	}

	accountID, errResult := common.RequiredPathID(params, "account_id")
	if errResult != nil {
		return "", "", errResult
	}

	return domainID, accountID, nil
}
