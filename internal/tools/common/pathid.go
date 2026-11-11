package common

import (
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// RequiredPathID reads a resource id that is interpolated into a PrivX REST path.
// An empty value is a missing-field error. A value that is not one path segment
// is rejected before the PrivX SDK is called.
func RequiredPathID(params map[string]any, key string) (string, *registry.ToolResult) {
	id := utils.StringFromMap(params, key)
	if id == "" {
		return "", registry.ErrorResult("validation error: missing required field: " + key)
	}

	if errResult := PathSegmentError(key, id); errResult != nil {
		return "", errResult
	}

	return id, nil
}

// OptionalPathID reads a resource id that is interpolated into a PrivX REST path
// when present. An absent or empty value is returned as "".
func OptionalPathID(params map[string]any, key string) (string, *registry.ToolResult) {
	id := utils.StringFromMap(params, key)
	if id == "" {
		return "", nil
	}

	if errResult := PathSegmentError(key, id); errResult != nil {
		return "", errResult
	}

	return id, nil
}

// PathSegmentError rejects a value that would change the REST path when
// interpolated into one segment. An empty value is accepted.
func PathSegmentError(key, value string) *registry.ToolResult {
	if utils.SinglePathSegment(value) {
		return nil
	}

	return registry.ErrorResult("validation error: " + key + " is not a single path segment")
}
