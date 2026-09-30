package common

import (
	"encoding/json"
	"fmt"
)

// UnmarshalSearch converts a nested MCP `search` parameter into T by
// round-tripping through JSON. Nil raw yields a zero T. Unknown JSON fields
// are dropped. validate, when non-nil, runs on the object before decoding.
func UnmarshalSearch[T any](raw any, validate func(map[string]any) error) (*T, error) {
	out := new(T)
	if raw == nil {
		return out, nil
	}

	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("search must be an object")
	}

	if validate != nil {
		if err := validate(m); err != nil {
			return nil, err
		}
	}

	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, out); err != nil {
		return nil, err
	}

	return out, nil
}
