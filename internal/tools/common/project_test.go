package common

import (
	"encoding/json"
	"testing"
)

func TestSelectObjectFields_OmitMissing(t *testing.T) {
	out := SelectObjectFields(map[string]any{"id": "h1", "extra": "x"}, []string{"id", "nope"}, OmitMissing)
	if out["id"] != "h1" {
		t.Errorf("id = %v", out["id"])
	}
	if _, ok := out["nope"]; ok {
		t.Error("missing field should be omitted")
	}
	if _, ok := out["extra"]; ok {
		t.Error("unrequested field should be omitted")
	}
}

func TestSelectObjectFields_NullMissing(t *testing.T) {
	out := SelectObjectFields(map[string]any{"id": "u1"}, []string{"id", "email"}, NullMissing)
	if out["id"] != "u1" {
		t.Errorf("id = %v", out["id"])
	}
	if v, ok := out["email"]; !ok {
		t.Fatal("email key must be present")
	} else if v != nil {
		t.Errorf("missing email = %v, want nil", v)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["email"] != nil {
		t.Errorf("JSON email = %v, want null", decoded["email"])
	}
}

func TestSelectArrayFields_SkipsNonMaps(t *testing.T) {
	items := []any{
		map[string]any{"id": "a", "drop": 1},
		"not-a-map",
		42,
		nil,
	}
	out := SelectArrayFields(items, []string{"id"}, OmitMissing)
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	m, ok := out[0].(map[string]any)
	if !ok || m["id"] != "a" {
		t.Errorf("got %#v", out[0])
	}
	if _, ok := m["drop"]; ok {
		t.Error("unrequested field should be omitted")
	}
}

func TestProjectArray_OmitMissingEmpty(t *testing.T) {
	got := ProjectArray(nil, []string{"id"}, OmitMissing)
	items, ok := got.([]any)
	if !ok {
		t.Fatalf("got %T, want []any", got)
	}
	if len(items) != 0 {
		t.Errorf("len = %d, want 0", len(items))
	}
}

func TestProjectArray_NullMissingNil(t *testing.T) {
	if got := ProjectArray(nil, []string{"id"}, NullMissing); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := ProjectArray("nope", []string{"id"}, NullMissing); got != nil {
		t.Errorf("non-array = %v, want nil", got)
	}
}

func TestProjectObject_NonObject(t *testing.T) {
	if got := ProjectObject(nil, []string{"enabled"}, NullMissing); got != nil {
		t.Errorf("nil = %v", got)
	}
	if got := ProjectObject("x", []string{"enabled"}, NullMissing); got != nil {
		t.Errorf("string = %v", got)
	}
}

func TestProjectObject_NullMissingFields(t *testing.T) {
	got := ProjectObject(map[string]any{"enabled": true}, []string{"enabled", "timezone"}, NullMissing)
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("got %T", got)
	}
	if m["enabled"] != true {
		t.Errorf("enabled = %v", m["enabled"])
	}
	if v, ok := m["timezone"]; !ok || v != nil {
		t.Errorf("timezone = %v ok=%v, want nil", v, ok)
	}
}
