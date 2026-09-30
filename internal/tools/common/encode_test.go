package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONResult_OK(t *testing.T) {
	result := JSONResult(map[string]any{
		"id":      "abc",
		"updated": true,
	})
	if result == nil {
		t.Fatal("expected result")
		return
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].Text), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["id"] != "abc" {
		t.Errorf("id = %v, want abc", got["id"])
	}
	if got["updated"] != true {
		t.Errorf("updated = %v, want true", got["updated"])
	}
}

func TestJSONResult_UnsupportedValue(t *testing.T) {
	result := JSONResult(make(chan int))
	if result == nil {
		t.Fatal("expected result")
		return
	}
	if !result.IsError {
		t.Fatal("expected error result")
	}
	if got := result.Content[0].Text; got != "failed to encode response" {
		t.Errorf("message = %q, want %q", got, "failed to encode response")
	}
}

func TestJSONResult_UnsupportedNestedValue(t *testing.T) {
	result := JSONResult(map[string]any{
		"ok":    "yes",
		"bad":   func() {},
		"items": []any{1, make(chan int)},
	})
	if result == nil || !result.IsError {
		t.Fatalf("expected error result, got %#v", result)
	}
	if !strings.Contains(result.Content[0].Text, "failed to encode response") {
		t.Errorf("message = %q", result.Content[0].Text)
	}
}
