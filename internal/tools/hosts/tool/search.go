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

// Search returns the host-search tool definition.
//
// Filters live in a nested `search` object; top-level inputs cover paging,
// sort, projection, and raw.
func Search() registry.Tool {
	description := "Search PrivX hosts by identity, endpoint, access, cloud, or state criteria. " +
		"Put filters in `search` (AND across fields, OR within arrays). " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0; prefer over host-list when filtering. " +
		`search.disabled is an enum string ("FALSE"|"BY_ADMIN"), not a boolean. ` +
		"For connection link creation guidance, see mcp-info -> context: connection. " +
		common.PresentationGuidance

	searchProps := registry.NewOrderedMap().
		Set("id", map[string]any{"type": "string", "description": "Host UUID."}).
		Set("keywords", map[string]any{"type": "string", "description": "Free-text across host fields."}).
		Set("distinguished_name", arrProp("Distinguished names (OR).")).
		Set("external_id", map[string]any{"type": "string", "description": "External-source host id."}).
		Set("instance_id", map[string]any{"type": "string", "description": "Cloud instance id."}).
		Set("source_id", map[string]any{"type": "string", "description": "Importer source UUID only (non-UUID source_id values will not match)."}).
		Set("common_name", arrProp("Common names (OR).")).
		Set("organization", arrProp("Organizations (OR).")).
		Set("organizational_unit", arrProp("Organizational units (OR).")).
		Set("address", arrProp("Addresses (OR).")).
		Set("service", arrProp(`Service types (OR), e.g. "ssh", "rdp", "web", "vnc", "db".`)).
		Set("port", map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Service ports (OR)."}).
		Set("zone", arrProp("Network zones (OR).")).
		Set("host_type", arrProp(`Host types (OR), e.g. "host", "aws-ec2", "azure-vm", "gcp-instance".`)).
		Set("host_classification", arrProp("Host classifications (OR).")).
		Set("role", arrProp("Role UUIDs granted on the host (OR); names not accepted.")).
		Set("scope", arrProp("Scopes (OR).")).
		Set("tags", arrProp("Tags (OR).")).
		Set("access_group_ids", arrProp("Access group UUIDs (OR).")).
		Set("cloud_providers", arrProp(`Cloud providers (OR), e.g. "aws", "azure", "gcp".`)).
		Set("cloud_provider_regions", arrProp(`Cloud regions (OR), e.g. "eu-west-1".`)).
		Set("deployable", map[string]any{"type": "boolean", "description": "Deployable flag."}).
		Set("statuses", arrProp("Service health-check statuses (OR).")).
		Set("disabled", map[string]any{"type": "string", "description": `Enum string, not boolean: "FALSE" (enabled), "BY_ADMIN" (admin-disabled). Case-insensitive; "true" matches nothing.`}).
		Set("ignore_disabled_sources", map[string]any{"type": "boolean", "description": "Exclude hosts from disabled sources."}).
		Set("filter", map[string]any{"type": "string", "description": "Raw PrivX filter expression when structured fields are insufficient."})

	searchObject := registry.NewOrderedMap().
		Set("type", "object").
		Set("description", "Optional PrivX HostSearch fields (snake_case).").
		Set("properties", searchProps).
		Set("additionalProperties", false)

	properties := registry.NewOrderedMap().
		Set("search", searchObject).
		Set("limit", map[string]any{"type": "integer", "minimum": 1, "description": fmt.Sprintf("Page size. Default %d.", common.HostsListLimit)}).
		Set("offset", map[string]any{"type": "integer", "minimum": 0, "description": "Record offset (not page number). Next page: offset+limit."}).
		Set("sortKey", common.SortKeySchemaWithExamples(`"common_name", "updated"`)).
		Set("sortDir", common.SortDirSchema()).
		Set("fields", map[string]any{"type": "string", "description": "Extra root fields CSV beyond defaults (id, common_name, addresses, disabled, services, principals). Ignored if raw."}).
		Set("serviceFields", map[string]any{"type": "string", "description": "Extra service fields CSV beyond defaults (service, address, status). Ignored if raw."}).
		Set("principalFields", map[string]any{"type": "string", "description": "Extra principal fields CSV beyond defaults (principal, roles). Ignored if raw."}).
		Set("raw", map[string]any{"type": "boolean", "default": false, "description": "Skip field projection. Sensitive fields are omitted. Large payloads."})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "host-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchHostsHandler,
	}
}

// arrProp returns a string-array property schema with the given description.
func arrProp(description string) map[string]any {
	return map[string]any{
		"type":        "array",
		"items":       map[string]any{"type": "string"},
		"description": description,
	}
}

func searchHostsHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.HostsListLimit)
	if errResult != nil {
		return errResult, nil
	}

	raw := utils.BoolFromMap(params, "raw")

	search, err := buildHostSearch(params["search"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid search body: %v", err)), nil
	}

	client := hoststore.New(authCtx.Connector)

	result, err := client.SearchHosts(search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search hosts: %v", err)), nil
	}

	items := hosts.FormatHostItems(result.Items, raw, hosts.ProjectionFromParams(params))

	return common.JSONPage(paging, items, result.Count, len(result.Items)), nil
}

// buildHostSearch converts the nested `search` parameter (a map[string]any
// from the MCP client) into a hoststore.HostSearch by round-tripping through
// JSON. Unknown fields are dropped; only provided fields are sent. The
// `disabled` field is a stored enum string (e.g. "FALSE", "BY_ADMIN"), not a
// boolean; we reject non-string values rather than silently coercing them,
// because a coerced "true" matches no hosts on the server side.
func buildHostSearch(raw any) (*hoststore.HostSearch, error) {
	return common.UnmarshalSearch[hoststore.HostSearch](raw, func(m map[string]any) error {
		if d, ok := m["disabled"]; ok {
			if _, ok := d.(string); !ok {
				return fmt.Errorf("search.disabled must be a string (the stored enum value, e.g. \"FALSE\" or \"BY_ADMIN\"); booleans are not accepted")
			}
		}

		return nil
	})
}
