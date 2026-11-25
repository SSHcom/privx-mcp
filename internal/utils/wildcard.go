package utils

import "strings"

// MinWildcardLiterals is the number of non-'*' characters a pattern with a
// '*' needs to be usable. Shorter wildcard patterns, including "*" alone, are
// ignored.
const MinWildcardLiterals = 3

// UsableWildcard reports whether pattern takes part in matching. A pattern
// without '*' is always usable. A pattern with '*' needs at least
// MinWildcardLiterals other characters.
func UsableWildcard(pattern string) bool {
	stars := strings.Count(pattern, "*")

	return stars == 0 || len(pattern)-stars >= MinWildcardLiterals
}

// UsableWildcards returns the patterns that UsableWildcard accepts, in order.
func UsableWildcards(patterns []string) []string {
	usable := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if UsableWildcard(pattern) {
			usable = append(usable, pattern)
		}
	}

	return usable
}

// MatchWildcard reports whether value matches pattern. A '*' in pattern
// matches any run of characters, including none. A pattern without '*' must
// equal value exactly. Matching is case-sensitive. A pattern that
// UsableWildcard rejects never matches.
//
//	"host-list" matches only "host-list"
//	"*-list"    matches names ending in "-list"
//	"host-*"    matches names starting with "host-"
//	"*secret*"  matches names containing "secret"
func MatchWildcard(value, pattern string) bool {
	if !UsableWildcard(pattern) {
		return false
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return value == pattern
	}

	first, last := parts[0], parts[len(parts)-1]
	if len(value) < len(first)+len(last) || !strings.HasPrefix(value, first) || !strings.HasSuffix(value, last) {
		return false
	}

	middle := value[len(first) : len(value)-len(last)]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(middle, part)
		if idx < 0 {
			return false
		}

		middle = middle[idx+len(part):]
	}

	return true
}

// MatchAnyWildcard reports whether value matches at least one of patterns.
// See MatchWildcard for the pattern syntax.
func MatchAnyWildcard(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if MatchWildcard(value, pattern) {
			return true
		}
	}

	return false
}
