package runtime

import (
	"encoding/json"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

func TestConvertTool_DescriptionPreserved(t *testing.T) {
	tool := registry.Tool{
		Name:        "host-list",
		Description: "Lists hosts from PrivX Host Store.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer"},
			},
		},
	}

	converted := convertTool(tool)
	if converted.Description != tool.Description {
		t.Fatalf("expected description %q, got %q", tool.Description, converted.Description)
	}
	if converted.Title != "Host List" {
		t.Fatalf("expected title %q, got %q", "Host List", converted.Title)
	}
	if converted.Annotations == nil || !converted.Annotations.ReadOnlyHint {
		t.Fatal("expected readOnlyHint for a non-write tool")
	}
	if converted.InputSchema == nil {
		t.Fatal("expected non-nil input schema")
	}
}

func TestConvertTool_NoInputSchema(t *testing.T) {
	tool := registry.Tool{
		Name:        "echo",
		Description: "Echoes back the input.",
	}

	converted := convertTool(tool)
	if converted.Description != tool.Description {
		t.Fatalf("expected description %q, got %q", tool.Description, converted.Description)
	}
	raw, ok := converted.InputSchema.(json.RawMessage)
	if !ok {
		t.Fatalf("expected json.RawMessage schema, got %T", converted.InputSchema)
	}
	if string(raw) != `{"type":"object"}` {
		t.Fatalf("expected empty object schema, got %s", raw)
	}
}
