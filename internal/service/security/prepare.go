package security

import "strings"

// ContainsRedacted reports whether any string value reachable from v contains
// the response-filter marker [redacted]. Map keys are not inspected.
func ContainsRedacted(v any) bool {
	switch value := v.(type) {
	case string:
		return strings.Contains(value, redacted)
	case map[string]any:
		for _, element := range value {
			if ContainsRedacted(element) {
				return true
			}
		}
	case []any:
		for _, element := range value {
			if ContainsRedacted(element) {
				return true
			}
		}
	}

	return false
}

// PrepareStrings sanitizes the given strings in place and replaces whole words
// from filter. It exists for trusted payloads (see registry.Tool.Trusted) that
// still embed individual PrivX-sourced strings, which the runtime no longer
// inspects. An empty filter only sanitizes.
func PrepareStrings(filter Filter, values ...*string) {
	for _, value := range values {
		if value == nil {
			continue
		}

		*value = filter.Redact(Sanitize(*value))
	}
}

// Prepare sanitizes every string value reachable from v. Only values are
// inspected; map keys are left alone, so a field named "email" or "delete" is
// never changed by itself.
//
// Maps and slices are mutated in place and a sanitized string is written back
// only when sanitizing actually changed it. The returned value differs from v
// only when v is a string itself.
func Prepare(v any) any {
	return walk(v, Filter{}, nil)
}

// PrepareExcept sanitizes like Prepare, leaving every string under paths
// unchanged. A path is dot-separated. A segment ending in [] walks each object
// in that array. The named value and everything under it are kept. Other
// strings are still sanitized. An empty path list is Prepare.
func PrepareExcept(v any, paths []string) any {
	return walk(v, Filter{}, splitPaths(paths))
}

// PrepareResponse sanitizes every string value reachable from v, then replaces
// whole words from filter. An empty filter only sanitizes. The walk rules match
// Prepare.
func PrepareResponse(v any, filter Filter) any {
	return walk(v, filter, nil)
}

// PrepareResponseExcept sanitizes and word-filters like PrepareResponse, leaving
// every string under paths unchanged. Path rules match PrepareExcept. An empty
// path list is PrepareResponse.
func PrepareResponseExcept(v any, filter Filter, paths []string) any {
	return walk(v, filter, splitPaths(paths))
}

func walk(v any, filter Filter, keep [][]string) any {
	if kept(keep) {
		return v
	}

	switch value := v.(type) {
	case string:
		return filter.Redact(Sanitize(value))
	case map[string]any:
		for key, element := range value {
			next := narrow(keep, key)
			if kept(next) {
				continue
			}

			clean := walk(element, filter, next)
			if _, isString := element.(string); isString && clean != element {
				value[key] = clean
			}
		}
	case []any:
		for i, element := range value {
			clean := walk(element, filter, keep)
			if _, isString := element.(string); isString && clean != element {
				value[i] = clean
			}
		}
	}

	return v
}

func splitPaths(paths []string) [][]string {
	if len(paths) == 0 {
		return nil
	}

	out := make([][]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}

		out = append(out, strings.Split(path, "."))
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func kept(keep [][]string) bool {
	for _, path := range keep {
		if len(path) == 0 {
			return true
		}
	}

	return false
}

func narrow(keep [][]string, key string) [][]string {
	if len(keep) == 0 {
		return nil
	}

	var next [][]string
	for _, path := range keep {
		if len(path) == 0 {
			return [][]string{nil}
		}

		if strings.TrimSuffix(path[0], "[]") != key {
			continue
		}

		if next == nil {
			next = make([][]string, 0, 1)
		}

		next = append(next, path[1:])
	}

	return next
}
