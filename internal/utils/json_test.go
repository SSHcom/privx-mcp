package utils

import "testing"

func TestToJSONMap(t *testing.T) {
	type inner struct {
		B int `json:"b"`
	}
	type outer struct {
		A string `json:"a"`
		I inner  `json:"inner"`
	}
	m := ToJSONMap(outer{A: "x", I: inner{B: 2}})
	if m["a"] != "x" {
		t.Errorf("a = %v, want x", m["a"])
	}
	im, ok := m["inner"].(map[string]any)
	if !ok {
		t.Fatalf("inner not a map: %T", m["inner"])
	}
	if im["b"] != float64(2) {
		t.Errorf("inner.b = %v, want 2", im["b"])
	}
}

func TestToJSONMap_Unmarshalable(t *testing.T) {
	m := ToJSONMap(make(chan int))
	if m == nil || len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}
