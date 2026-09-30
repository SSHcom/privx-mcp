package tool

import (
	"testing"
)

func TestBuildHostSearch(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		s, err := buildHostSearch(nil)
		if err != nil || s == nil {
			t.Fatalf("got %v, err %v", s, err)
		}
	})
	t.Run("not object", func(t *testing.T) {
		_, err := buildHostSearch([]any{"x"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("disabled boolean rejected", func(t *testing.T) {
		_, err := buildHostSearch(map[string]any{"disabled": true})
		if err == nil {
			t.Fatal("expected error for boolean disabled")
		}
	})
	t.Run("disabled string accepted", func(t *testing.T) {
		s, err := buildHostSearch(map[string]any{"disabled": "BY_ADMIN", "keywords": "web"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if s.Disabled != "BY_ADMIN" {
			t.Errorf("disabled = %q", s.Disabled)
		}
		if s.Keywords != "web" {
			t.Errorf("keywords = %q", s.Keywords)
		}
	})
	t.Run("unknown fields dropped", func(t *testing.T) {
		s, err := buildHostSearch(map[string]any{"not_a_field": "x", "id": "h1"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if s.ID != "h1" {
			t.Errorf("id = %q", s.ID)
		}
	})
}
