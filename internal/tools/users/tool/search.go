package tool

import (
	"context"
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/users"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Search returns the user-search tool definition.
//
// Filters live in a nested `search` object. source_type is MCP-only and is
// applied by post-filtering the current PrivX page, so returned can be much
// smaller than limit. Pagination metadata still follows the unfiltered page.
func Search() registry.Tool {
	description := "Search PrivX users across local and directory sources. " +
		"Put filters in `search` (AND across fields, OR within arrays). " +
		"Sorted by created DESC by default. " +
		"Prefer over user-list when filtering. " +
		"IMPORTANT: search.source_type is applied after PrivX returns a page, so `returned` " +
		"can be much smaller than `limit` (even 0). `limit`/`count`/`remaining`/`pagesRemaining` " +
		"follow the unfiltered PrivX page. Stop only when nextOffset is null — never because " +
		"returned < limit. " +
		common.PresentationGuidance

	searchProps := registry.NewOrderedMap().
		Set("keywords", map[string]any{
			"type":        "string",
			"description": "Free-text across user fields.",
		}).
		Set("source", map[string]any{
			"type":        "string",
			"description": "Directory source UUID.",
		}).
		Set("source_type", map[string]any{
			"type": "string",
			"description": "Directory type (LOCAL, AD, MICROSOFTGRAPH, …). " +
				"MCP-only post-filter on the current unfiltered PrivX page: matching items are kept, " +
				"others dropped, so this page may return far fewer than `limit`. " +
				"Keep calling with nextOffset until it is null to collect all matches.",
		}).
		Set("user_id", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "User UUIDs.",
		})

	searchObject := registry.NewOrderedMap().
		Set("type", "object").
		Set("description", "Optional PrivX UserSearch fields plus MCP-only source_type post-filter (snake_case).").
		Set("properties", searchProps).
		Set("additionalProperties", false)

	properties := registry.NewOrderedMap().
		Set("search", searchObject).
		Set("limit", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": fmt.Sprintf("Unfiltered PrivX page size (default %d). With source_type, returned matches on this page may be fewer.", common.UsersListLimit),
		}).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Unfiltered record offset (not page number). Next call: nextOffset from the previous response.",
		}).
		Set("sortKey", common.SortKeySchemaWithExamples(`"principal", "updated"`)).
		Set("sortDir", common.SortDirSchema()).
		Set("fields", map[string]any{"type": "string", "description": "Extra root fields CSV beyond defaults (id, principal, source, source_type, email, full_name, roles). Ignored if raw."}).
		Set("roleFields", map[string]any{"type": "string", "description": "Extra role fields CSV beyond defaults (id, name). Ignored if raw."}).
		Set("raw", map[string]any{"type": "boolean", "default": false, "description": "Skip field projection. Sensitive fields are omitted. Large payloads."})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-search",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     searchUsersHandler,
	}
}

func searchUsersHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.UsersListLimit)
	if errResult != nil {
		return errResult, nil
	}

	raw := utils.BoolFromMap(params, "raw")

	search, sourceType, err := buildUserSearch(params["search"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: invalid search body: %v", err)), nil
	}

	client := rolestore.New(authCtx.Connector)

	result, err := client.SearchUsers(*search, paging.FilterOptions()...)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search users: %v", err)), nil
	}

	// Pagination metadata follows the unfiltered PrivX page so callers can
	// advance offset while pagesRemaining > 0 even when source_type drops items.
	fetched := len(result.Items)
	items := filterUsersBySourceType(result.Items, sourceType)
	formatted := users.FormatUserItems(items, raw, users.ProjectionFromParams(params))

	return common.JSONPage(
		paging,
		formatted,
		result.Count,
		fetched,
		common.WithReturned(len(items)),
		common.WithNextOffset(),
	), nil
}

func filterUsersBySourceType(items []rolestore.User, sourceType string) []rolestore.User {
	if sourceType == "" {
		return items
	}

	out := make([]rolestore.User, 0, len(items))
	for _, u := range items {
		if utils.EqualFoldTrimmed(u.SourceType, sourceType) {
			out = append(out, u)
		}
	}

	return out
}

// buildUserSearch converts the nested `search` parameter (a map[string]any
// from the MCP client) into a rolestore.UserSearch by round-tripping through
// JSON. source_type is extracted separately because PrivX UserSearch does not
// accept it. Other unknown fields are dropped; only provided API fields are sent.
func buildUserSearch(raw any) (*rolestore.UserSearch, string, error) {
	var sourceType string

	search, err := common.UnmarshalSearch[rolestore.UserSearch](raw, func(m map[string]any) error {
		sourceType = strings.TrimSpace(utils.StringFromMap(m, "source_type"))

		return nil
	})
	if err != nil {
		return nil, "", err
	}

	return search, sourceType, nil
}
