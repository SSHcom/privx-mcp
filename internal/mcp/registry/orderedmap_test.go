package registry

import (
	"encoding/json"
	"testing"
)

func TestOrderedMap_PreservesInsertionOrder(t *testing.T) {
	props := NewOrderedMap().
		Set("fields", "x").
		Set("serviceFields", "x").
		Set("principalFields", "x").
		Set("raw", "x").
		Set("limit", "x").
		Set("offset", "x")
	schema := NewOrderedMap().
		Set("type", "object").
		Set("properties", props)

	b, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := `{"type":"object","properties":{"fields":"x","serviceFields":"x","principalFields":"x","raw":"x","limit":"x","offset":"x"}}`
	if string(b) != want {
		t.Fatalf("expected %s, got %s", want, string(b))
	}
}
