package common

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default sort for list/search tools whose models expose a created field.
const (
	DefaultSortKey = "created"
	DefaultSortDir = "DESC"
)

// Paging holds validated limit, offset, and sort options for PrivX list/search calls.
type Paging struct {
	Limit   int
	Offset  int
	SortKey string
	SortDir string
}

// ParsePaging extracts limit, offset, and sort options from MCP params.
// Empty sortKey/sortDir default to created / DESC.
func ParsePaging(params map[string]any, defaultLimit int) (Paging, *registry.ToolResult) {
	limit, err := utils.IntFromMap(params, "limit", defaultLimit)
	if err != nil {
		return Paging{}, registry.ErrorResult(fmt.Sprintf("validation error: %v", err))
	}

	if limit < 1 {
		return Paging{}, registry.ErrorResult("validation error: limit must be >= 1")
	}

	offset, err := utils.IntFromMap(params, "offset", 0)
	if err != nil {
		return Paging{}, registry.ErrorResult(fmt.Sprintf("validation error: %v", err))
	}

	if offset < 0 {
		return Paging{}, registry.ErrorResult("validation error: offset must be >= 0")
	}

	sortKey := utils.StringFromMap(params, "sortKey")
	sortDir := utils.StringFromMap(params, "sortDir")

	if sortKey == "" {
		sortKey = DefaultSortKey
	}

	if sortDir == "" {
		sortDir = DefaultSortDir
	}

	if sortDir != "ASC" && sortDir != "DESC" {
		return Paging{}, registry.ErrorResult("validation error: sortDir must be ASC or DESC")
	}

	return Paging{
		Limit:   limit,
		Offset:  offset,
		SortKey: sortKey,
		SortDir: sortDir,
	}, nil
}

// FilterOptions returns PrivX SDK paging and sort options.
func (p Paging) FilterOptions() []filters.Option {
	return []filters.Option{
		filters.Paging(p.Offset, p.Limit),
		filters.Sort(p.SortKey, p.SortDir),
	}
}

// SortKeySchema returns the JSON Schema property for sortKey.
func SortKeySchema() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": fmt.Sprintf(`Sort key. Defaults to %q.`, DefaultSortKey),
	}
}

// SortDirSchema returns the JSON Schema property for sortDir.
func SortDirSchema() map[string]any {
	return map[string]any{
		"type":        "string",
		"enum":        []string{"ASC", "DESC"},
		"description": fmt.Sprintf(`Sort direction. Defaults to %q.`, DefaultSortDir),
	}
}

// SortKeySchemaWithExamples returns sortKey schema with topic-specific examples.
func SortKeySchemaWithExamples(examples string) map[string]any {
	return map[string]any{
		"type":        "string",
		"description": fmt.Sprintf(`Sort key (e.g. %s). Defaults to %q.`, examples, DefaultSortKey),
	}
}

type pageOptions struct {
	returned    int
	setReturned bool
	nextOffset  bool
	extra       map[string]any
}

// PageOption customizes a list/search paging envelope.
type PageOption func(*pageOptions)

// WithReturned overrides the `returned` field. Remaining/nextOffset still use fetched.
func WithReturned(n int) PageOption {
	return func(o *pageOptions) {
		o.returned = n
		o.setReturned = true
	}
}

// WithNextOffset includes nextOffset (null when this is the last page).
func WithNextOffset() PageOption {
	return func(o *pageOptions) {
		o.nextOffset = true
	}
}

// WithExtra adds an extra envelope field such as filter.
func WithExtra(key string, value any) PageOption {
	return func(o *pageOptions) {
		if o.extra == nil {
			o.extra = make(map[string]any)
		}

		o.extra[key] = value
	}
}

// JSONPage encodes a list/search envelope. fetched is the unfiltered PrivX
// page size used for remaining (and nextOffset). returned defaults to fetched.
func JSONPage(paging Paging, items any, count, fetched int, opts ...PageOption) *registry.ToolResult {
	var o pageOptions
	for _, opt := range opts {
		opt(&o)
	}

	returned := fetched
	if o.setReturned {
		returned = o.returned
	}

	remaining := count - (paging.Offset + fetched)
	if remaining < 0 {
		remaining = 0
	}

	var pagesRemaining int
	if paging.Limit > 0 {
		pagesRemaining = (remaining + paging.Limit - 1) / paging.Limit
	}

	payload := map[string]any{
		"items":          items,
		"count":          count,
		"limit":          paging.Limit,
		"offset":         paging.Offset,
		"returned":       returned,
		"remaining":      remaining,
		"pagesRemaining": pagesRemaining,
	}

	if o.nextOffset {
		var nextOffset any
		if remaining > 0 && fetched > 0 {
			nextOffset = paging.Offset + fetched
		}

		payload["nextOffset"] = nextOffset
	}

	for k, v := range o.extra {
		payload[k] = v
	}

	return JSONResult(payload)
}
