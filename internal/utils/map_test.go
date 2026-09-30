package utils

import (
	"testing"
)

func TestCSVFromMap(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want []string
	}{
		{"absent", map[string]any{}, "fields", nil},
		{"empty", map[string]any{"fields": ""}, "fields", nil},
		{"single", map[string]any{"fields": "id"}, "fields", []string{"id"}},
		{"csv with spaces", map[string]any{"fields": " id , common_name , "}, "fields", []string{"id", "common_name"}},
		{"wrong type", map[string]any{"fields": 42}, "fields", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CSVFromMap(tc.m, tc.key)
			if !equalStrings(got, tc.want) {
				t.Errorf("CSVFromMap = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringFromMap(t *testing.T) {
	if got := StringFromMap(map[string]any{"name": "alice"}, "name"); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
	if got := StringFromMap(map[string]any{}, "name"); got != "" {
		t.Errorf("absent got %q, want empty", got)
	}
	if got := StringFromMap(map[string]any{"name": 123}, "name"); got != "" {
		t.Errorf("wrong type got %q, want empty", got)
	}
}

func TestOverlayString(t *testing.T) {
	s, ok, err := OverlayString(map[string]any{}, "comment")
	if err != nil || ok || s != "" {
		t.Fatalf("absent: %q ok=%v err=%v", s, ok, err)
	}
	s, ok, err = OverlayString(map[string]any{"comment": ""}, "comment")
	if err != nil || !ok || s != "" {
		t.Fatalf("empty: %q ok=%v err=%v", s, ok, err)
	}
	s, ok, err = OverlayString(map[string]any{"comment": "hi"}, "comment")
	if err != nil || !ok || s != "hi" {
		t.Fatalf("string: %q ok=%v err=%v", s, ok, err)
	}
	_, _, err = OverlayString(map[string]any{"comment": 1}, "comment")
	if err == nil {
		t.Fatal("expected error for non-string")
	}
}

func TestOverlayBool(t *testing.T) {
	b, ok, err := OverlayBool(map[string]any{}, "flag")
	if err != nil || ok || b {
		t.Fatalf("absent: %v ok=%v err=%v", b, ok, err)
	}
	b, ok, err = OverlayBool(map[string]any{"flag": true}, "flag")
	if err != nil || !ok || !b {
		t.Fatalf("true: %v ok=%v err=%v", b, ok, err)
	}
	b, ok, err = OverlayBool(map[string]any{"flag": "false"}, "flag")
	if err != nil || !ok || b {
		t.Fatalf("false string: %v ok=%v err=%v", b, ok, err)
	}
	_, _, err = OverlayBool(map[string]any{"flag": 1}, "flag")
	if err == nil {
		t.Fatal("expected error for non-bool")
	}
}

func TestBoolFromMap(t *testing.T) {
	tests := []struct {
		in   any
		want bool
	}{
		{nil, false}, {true, true}, {false, false},
		{"true", true}, {"TRUE", true}, {"True", true},
		{"false", false}, {"anything", false}, {42, false},
	}
	for _, tc := range tests {
		if got := BoolFromMap(map[string]any{"raw": tc.in}, "raw"); got != tc.want {
			t.Errorf("BoolFromMap(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIntFromMap(t *testing.T) {
	got, err := IntFromMap(map[string]any{}, "limit", 50)
	if err != nil || got != 50 {
		t.Fatalf("absent: got %d, err %v, want 50", got, err)
	}
	got, err = IntFromMap(map[string]any{"limit": float64(10)}, "limit", 50)
	if err != nil || got != 10 {
		t.Fatalf("float64: got %d, err %v, want 10", got, err)
	}
	got, err = IntFromMap(map[string]any{"limit": 7}, "limit", 50)
	if err != nil || got != 7 {
		t.Fatalf("int: got %d, err %v, want 7", got, err)
	}
	_, err = IntFromMap(map[string]any{"limit": 1.5}, "limit", 50)
	if err == nil {
		t.Fatal("expected error for non-integer float")
	}
	_, err = IntFromMap(map[string]any{"limit": "10"}, "limit", 50)
	if err == nil {
		t.Fatal("expected error for string")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
