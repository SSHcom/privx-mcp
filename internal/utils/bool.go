package utils

import "fmt"

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
