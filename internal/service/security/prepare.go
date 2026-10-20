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
	return walk(v, Filter{})
}

// PrepareResponse sanitizes every string value reachable from v, then replaces
// whole words from filter. An empty filter only sanitizes. The walk rules match
// Prepare.
func PrepareResponse(v any, filter Filter) any {
	return walk(v, filter)
}

func walk(v any, filter Filter) any {
	switch value := v.(type) {
	case string:
		return filter.Redact(Sanitize(value))
	case map[string]any:
		for key, element := range value {
			clean := walk(element, filter)
			if _, isString := element.(string); isString && clean != element {
				value[key] = clean
			}
		}
	case []any:
		for i, element := range value {
			clean := walk(element, filter)
			if _, isString := element.(string); isString && clean != element {
				value[i] = clean
			}
		}
	}

	return v
}
