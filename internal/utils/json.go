package utils

import "encoding/json"

// ToJSONMap marshals a value to a generic map[string]any using its JSON tags.
// On marshal or unmarshal failure it returns an empty map.
func ToJSONMap(v any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{}
	}

	return m
}
