package security

import (
	"encoding/json"
	"testing"
)

func TestWrap_ObjectPayload(t *testing.T) {
	wrapped, err := Wrap(map[string]any{"count": 1, "items": []any{"host-a"}})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}

	var decoded struct {
		Meta envelopeMeta   `json:"meta"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(wrapped, &decoded); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}

	if decoded.Meta.Origin != metaOrigin {
		t.Errorf("expected origin %q, got %q", metaOrigin, decoded.Meta.Origin)
	}
	if decoded.Meta.InstructionAuthority != metaInstructionAuthority {
		t.Errorf("expected instruction_authority %q, got %q", metaInstructionAuthority, decoded.Meta.InstructionAuthority)
	}
	if decoded.Meta.Note != metaNote {
		t.Errorf("expected note %q, got %q", metaNote, decoded.Meta.Note)
	}
	if decoded.Data["count"] != float64(1) {
		t.Errorf("expected data.count 1, got %v", decoded.Data["count"])
	}
}

func TestWrap_StringPayload(t *testing.T) {
	wrapped, err := Wrap("plain text")
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}

	var decoded struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(wrapped, &decoded); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}
	if decoded.Data != "plain text" {
		t.Errorf("expected data %q, got %q", "plain text", decoded.Data)
	}
}
