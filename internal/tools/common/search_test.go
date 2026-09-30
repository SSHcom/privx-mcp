package common

import (
	"fmt"
	"strings"
	"testing"
)

type sampleSearch struct {
	Keywords string   `json:"keywords"`
	ID       string   `json:"id"`
	Tags     []string `json:"tags"`
}

func TestUnmarshalSearch_Nil(t *testing.T) {
	got, err := UnmarshalSearch[sampleSearch](nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil zero value")
		return
	}
	if got.Keywords != "" || got.ID != "" {
		t.Errorf("got %+v, want zero", got)
	}
}

func TestUnmarshalSearch_NotObject(t *testing.T) {
	_, err := UnmarshalSearch[sampleSearch]([]any{"x"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "search must be an object" {
		t.Errorf("err = %q", err.Error())
	}
}

func TestUnmarshalSearch_FieldsAndUnknownDropped(t *testing.T) {
	got, err := UnmarshalSearch[sampleSearch](map[string]any{
		"keywords":    "web",
		"id":          "h1",
		"tags":        []any{"a", "b"},
		"not_a_field": "x",
	}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Keywords != "web" || got.ID != "h1" {
		t.Errorf("got %+v", got)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "a" {
		t.Errorf("tags = %v", got.Tags)
	}
}

func TestUnmarshalSearch_Validate(t *testing.T) {
	_, err := UnmarshalSearch[sampleSearch](map[string]any{"keywords": 1}, func(m map[string]any) error {
		if _, ok := m["keywords"].(string); !ok {
			return fmt.Errorf("search.keywords must be a string")
		}

		return nil
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "search.keywords must be a string") {
		t.Errorf("err = %q", err.Error())
	}
}

func TestUnmarshalSearch_InvalidJSONType(t *testing.T) {
	_, err := UnmarshalSearch[sampleSearch](map[string]any{"tags": "not-an-array"}, nil)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}
