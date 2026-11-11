package utils

import (
	"fmt"
	"strings"
)

// AsBool coerces a boolean-ish value into a bool with strict validation.
// Unlike BoolFromMap (which silently defaults non-bool values to false), AsBool
// rejects non-boolean inputs.
func AsBool(v any) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		switch t {
		case "true", "True", "TRUE":
			return true, nil
		case "false", "False", "FALSE":
			return false, nil
		}

		return false, fmt.Errorf("must be a boolean")
	default:
		return false, fmt.Errorf("must be a boolean")
	}
}

// AsBoolExtended coerces a boolean-ish value the way AsBool does, and also
// accepts yes/no, on/off, and 1/0. String matching is case-insensitive, and
// surrounding spaces are ignored.
func AsBoolExtended(v any) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on":
			return true, nil
		case "0", "false", "no", "off":
			return false, nil
		}

		return false, fmt.Errorf("must be true, false, yes, no, on, off, 1, or 0")
	default:
		return false, fmt.Errorf("must be a boolean")
	}
}
