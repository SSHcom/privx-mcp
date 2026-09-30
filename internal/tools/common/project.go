package common

// MissingFieldMode controls how object projection treats keys absent from the source.
type MissingFieldMode int

const (
	// OmitMissing skips fields that are not present on the source object.
	OmitMissing MissingFieldMode = iota
	// NullMissing emits JSON null for fields that are not present on the source object.
	NullMissing
)

// SelectObjectFields copies the requested fields from m. Missing keys are either
// omitted or set to nil according to mode.
func SelectObjectFields(m map[string]any, fields []string, mode MissingFieldMode) map[string]any {
	out := make(map[string]any, len(fields))
	for _, field := range fields {
		if value, ok := m[field]; ok {
			out[field] = value
			continue
		}

		if mode == NullMissing {
			out[field] = nil
		}
	}

	return out
}

// SelectArrayFields projects each map in items with SelectObjectFields.
// Non-map entries are skipped.
func SelectArrayFields(items []any, fields []string, mode MissingFieldMode) []any {
	selected := make([]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		selected = append(selected, SelectObjectFields(m, fields, mode))
	}

	return selected
}

// ProjectArray projects a nested JSON array field.
//
// NullMissing: nil or a non-array value becomes nil (JSON null).
// OmitMissing: nil or a non-array value becomes an empty array, matching
// hosts/API-target nested arrays that are always present when requested.
func ProjectArray(raw any, fields []string, mode MissingFieldMode) any {
	items, ok := raw.([]any)
	if !ok {
		if mode == NullMissing {
			return nil
		}

		return []any{}
	}

	return SelectArrayFields(items, fields, mode)
}

// ProjectObject projects a nested JSON object field.
// Nil or a non-object value becomes nil.
func ProjectObject(raw any, fields []string, mode MissingFieldMode) any {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	return SelectObjectFields(m, fields, mode)
}
