package utils

import (
	"fmt"
	"strings"
)

// EqualFoldTrimmed compares strings after trimming surrounding whitespace.
func EqualFoldTrimmed(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// TrimLower normalizes a string for case-insensitive matching.
func TrimLower(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// SplitCSV splits s on commas into trimmed, non-empty tokens.
func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}

	var out []string

	for _, part := range strings.Split(s, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}

	return out
}

// MergeUnique returns base followed by any extras that are not already present.
func MergeUnique(base, extras []string) []string {
	seen := make(map[string]struct{}, len(base))

	merged := make([]string, 0, len(base)+len(extras))
	for _, f := range base {
		if _, ok := seen[f]; !ok {
			merged = append(merged, f)
			seen[f] = struct{}{}
		}
	}

	for _, f := range extras {
		if _, ok := seen[f]; !ok {
			merged = append(merged, f)
			seen[f] = struct{}{}
		}
	}

	return merged
}

// ToStringSlice converts a value into a non-empty-element string slice.
func ToStringSlice(raw any) ([]string, error) {
	if raw == nil {
		return nil, fmt.Errorf("must be an array")
	}

	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}

	out := make([]string, 0, len(arr))
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element %d must be a string", i)
		}

		if s == "" {
			return nil, fmt.Errorf("element %d must not be empty", i)
		}

		out = append(out, s)
	}

	return out, nil
}
