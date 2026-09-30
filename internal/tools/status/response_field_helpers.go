package status

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultComponentFields returns the dotted paths used by status-components
// and status-instance when raw is false. The returned slice is a fresh copy.
func DefaultComponentFields() []string {
	return []string{
		"component_name",
		"component_type",
		"status.status",
		"status.start_time",
	}
}

// DecodeJSON unmarshals a monitor-service raw JSON payload.
func DecodeJSON(raw *json.RawMessage) (any, error) {
	if raw == nil || len(*raw) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	var v any
	if err := json.Unmarshal(*raw, &v); err != nil {
		return nil, err
	}

	return v, nil
}

// SelectDottedFields copies the requested dotted paths from src into a new
// map, merging nested objects. Missing paths are skipped.
func SelectDottedFields(src map[string]any, paths []string) map[string]any {
	out := make(map[string]any)
	if src == nil {
		return out
	}

	for _, path := range paths {
		parts := splitPath(path)
		if len(parts) == 0 {
			continue
		}

		val, ok := lookupPath(src, parts)
		if !ok {
			continue
		}

		setPath(out, parts, val)
	}

	return out
}

// FormatComponents projects a components payload into hostname → []component.
// When payload is a bare array, it is wrapped under wrapHostname.
func FormatComponents(payload any, wrapHostname string, raw bool, fields []string) map[string][]map[string]any {
	switch typed := payload.(type) {
	case []any:
		return map[string][]map[string]any{
			wrapHostname: formatComponentItems(typed, raw, fields),
		}
	case map[string]any:
		if isHostnameComponentMap(typed) {
			out := make(map[string][]map[string]any, len(typed))
			for host, val := range typed {
				arr, _ := val.([]any)
				out[host] = formatComponentItems(arr, raw, fields)
			}

			return out
		}

		host := wrapHostname

		return map[string][]map[string]any{
			host: {formatComponentMap(typed, raw, fields)},
		}
	default:
		return map[string][]map[string]any{}
	}
}

// FormatInstance projects the instance status payload (an array of
// components, same shape as status-components) into a list of projected
// component maps. When raw is true the payload is returned unchanged.
func FormatInstance(payload any, raw bool, fields []string) any {
	if raw {
		return payload
	}

	arr, ok := payload.([]any)
	if !ok {
		return payload
	}

	if len(fields) == 0 {
		fields = DefaultComponentFields()
	}

	return formatComponentItems(arr, false, fields)
}

func formatComponentItems(items []any, raw bool, fields []string) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		out = append(out, formatComponentMap(m, raw, fields))
	}

	return out
}

func formatComponentMap(m map[string]any, raw bool, fields []string) map[string]any {
	if raw {
		return m
	}

	return SelectDottedFields(m, fields)
}

func isHostnameComponentMap(m map[string]any) bool {
	if len(m) == 0 {
		return true
	}

	for _, v := range m {
		if _, ok := v.([]any); !ok {
			return false
		}
	}

	return true
}

func splitPath(path string) []string {
	parts := strings.Split(path, ".")

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		out = append(out, p)
	}

	return out
}

func lookupPath(m map[string]any, parts []string) (any, bool) {
	cur := any(m)
	for _, p := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}

		next, ok := obj[p]
		if !ok {
			return nil, false
		}

		cur = next
	}

	return cur, true
}

func setPath(out map[string]any, parts []string, val any) {
	cur := out

	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = val
			return
		}

		next, ok := cur[p].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[p] = next
		}

		cur = next
	}
}
