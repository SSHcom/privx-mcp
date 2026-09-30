package utils

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StringFromMap reads a string value from m and returns "" when absent or wrong type.
func StringFromMap(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// OverlayString returns the string at key when present. Absent keys yield
// ok=false. A present non-string is an error (it is not coerced to empty).
func OverlayString(m map[string]any, key string) (value string, ok bool, err error) {
	v, ok := m[key]
	if !ok {
		return "", false, nil
	}

	s, ok := v.(string)
	if !ok {
		return "", false, fmt.Errorf("%s must be a string", key)
	}

	return s, true, nil
}

// OverlayBool returns the bool at key when present. Absent keys yield
// ok=false. A present value that AsBool rejects is an error (it is not
// coerced to false).
func OverlayBool(m map[string]any, key string) (value, ok bool, err error) {
	v, ok := m[key]
	if !ok {
		return false, false, nil
	}

	b, err := AsBool(v)
	if err != nil {
		return false, false, fmt.Errorf("%s must be a boolean", key)
	}

	return b, true, nil
}

// CSVFromMap reads a string value from m and splits it into trimmed, non-empty CSV tokens.
func CSVFromMap(m map[string]any, key string) []string {
	return SplitCSV(StringFromMap(m, key))
}

// BoolFromMap reads a boolean value from m and returns false when absent.
// String values equal to "true" (case-insensitive) are treated as true; other
// non-bool types return false.
func BoolFromMap(m map[string]any, key string) bool {
	value, ok := m[key]
	if !ok {
		return false
	}

	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

// IntFromMap reads an integer value from m, returning defaultValue when absent.
func IntFromMap(m map[string]any, key string, defaultValue int) (int, error) {
	value, ok := m[key]
	if !ok {
		return defaultValue, nil
	}

	switch typed := value.(type) {
	case float64:
		if typed != float64(int(typed)) {
			return 0, fmt.Errorf("%s must be an integer", key)
		}

		return int(typed), nil
	case int:
		return typed, nil
	case json.Number:
		n, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", key)
		}

		return int(n), nil
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
}
