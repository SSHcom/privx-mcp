package security

import (
	"context"
	"regexp"
	"strings"
)

const redacted = "[redacted]"

// Filter replaces configured whole words in tool response strings.
// The zero value replaces nothing.
type Filter struct {
	pattern *regexp.Regexp
}

// NewFilter builds a case-insensitive whole-word filter. Blank terms are
// ignored. An empty list, or a list of only blank terms, returns a filter
// that leaves every string unchanged.
func NewFilter(terms []string) Filter {
	quoted := make([]string, 0, len(terms))
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}

		quoted = append(quoted, regexp.QuoteMeta(term))
	}

	if len(quoted) == 0 {
		return Filter{}
	}

	return Filter{
		pattern: regexp.MustCompile(`(?i)\b(?:` + strings.Join(quoted, "|") + `)\b`),
	}
}

// Redact replaces each whole-word match with [redacted].
// It returns s unchanged when the filter has no terms.
func (f Filter) Redact(s string) string {
	if f.pattern == nil || s == "" {
		return s
	}

	return f.pattern.ReplaceAllString(s, redacted)
}

type filterContextKey struct{}

// ContextWithFilter stores filter for a trusted tool that redacts its own
// PrivX-sourced strings. mcp-info reads it; other tools ignore it.
func ContextWithFilter(ctx context.Context, filter Filter) context.Context {
	return context.WithValue(ctx, filterContextKey{}, filter)
}

// FilterFromContext returns the response filter stored by the runtime, or a
// no-op filter when none was stored.
func FilterFromContext(ctx context.Context) Filter {
	if ctx == nil {
		return Filter{}
	}

	filter, _ := ctx.Value(filterContextKey{}).(Filter)

	return filter
}
