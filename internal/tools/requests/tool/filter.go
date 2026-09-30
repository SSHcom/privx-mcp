package tool

import (
	"fmt"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// PrivX requires filter as a query parameter on list/search request endpoints.
// OpenAPI documents uppercase enums; the workflow-engine accepts lowercase on the wire
// (as used by the PrivX UI). We accept either case and always send lowercase.
const defaultRequestFilter = "all"

var validRequestFilters = map[string]string{
	"ALL":              "all",
	"ACTIVE_APPROVALS": "active_approvals",
	"APPROVALS":        "approvals",
	"REQUESTS":         "requests",
}

func requestFilterSchema() map[string]any {
	return map[string]any{
		"type":    "string",
		"default": "ALL",
		"enum": []string{
			"ALL",
			"ACTIVE_APPROVALS",
			"APPROVALS",
			"REQUESTS",
		},
		"description": "PrivX queue-scope query param (case-insensitive). " +
			"Default: ALL (all requests; can fail due to lack of permissions). " +
			"Options: APPROVALS (requests I can/did decide), ACTIVE_APPROVALS (pending approver's decision), " +
			"REQUESTS (requests I submitted), ALL (all requests; can fail due to lack of permissions).",
	}
}

func requestFilterFromMap(params map[string]any) (string, error) {
	raw := strings.TrimSpace(utils.StringFromMap(params, "filter"))
	// Clients often nest filter under search; PrivX needs it as a query param.
	if raw == "" {
		if search, ok := params["search"].(map[string]any); ok {
			raw = strings.TrimSpace(utils.StringFromMap(search, "filter"))
		}
	}

	if raw == "" {
		return defaultRequestFilter, nil
	}

	normalized, ok := validRequestFilters[strings.ToUpper(raw)]
	if !ok {
		return "", fmt.Errorf("filter must be one of: ALL, ACTIVE_APPROVALS, APPROVALS, REQUESTS")
	}

	return normalized, nil
}
