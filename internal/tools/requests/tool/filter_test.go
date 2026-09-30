package tool

import "testing"

func TestRequestFilterFromMap_Default(t *testing.T) {
	got, err := requestFilterFromMap(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "all" {
		t.Fatalf("got %q, want all", got)
	}
}

func TestRequestFilterFromMap_NormalizesToLowercaseWireValue(t *testing.T) {
	got, err := requestFilterFromMap(map[string]any{"filter": "ACTIVE_APPROVALS"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "active_approvals" {
		t.Fatalf("got %q, want active_approvals", got)
	}
}

func TestRequestFilterFromMap_Requests(t *testing.T) {
	got, err := requestFilterFromMap(map[string]any{"filter": "REQUESTS"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "requests" {
		t.Fatalf("got %q, want requests", got)
	}
}

func TestRequestFilterFromMap_RejectsRemovedFilters(t *testing.T) {
	if _, err := requestFilterFromMap(map[string]any{"filter": "ACTIVE_REQUESTS"}); err == nil {
		t.Fatal("expected error for removed filter ACTIVE_REQUESTS")
	}
}

func TestRequestFilterFromMap_Invalid(t *testing.T) {
	_, err := requestFilterFromMap(map[string]any{"filter": "pending"})
	if err == nil {
		t.Fatal("expected error for invalid filter")
	}
}

func TestRequestFilterFromMap_NestedUnderSearch(t *testing.T) {
	got, err := requestFilterFromMap(map[string]any{
		"search": map[string]any{"filter": "ALL", "keywords": "test@demo.net "},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "all" {
		t.Fatalf("got %q, want all", got)
	}
}

func TestRequestFilterFromMap_TopLevelWinsOverSearch(t *testing.T) {
	got, err := requestFilterFromMap(map[string]any{
		"filter": "APPROVALS",
		"search": map[string]any{"filter": "ALL"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "approvals" {
		t.Fatalf("got %q, want approvals", got)
	}
}

func TestBuildAccessRequestSearch_StripsBodyFilter(t *testing.T) {
	search, err := buildAccessRequestSearch(map[string]any{
		"keywords": "test@demo.net ",
		"filter":   "APPROVALS",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if search.Keywords != "test@demo.net" {
		t.Fatalf("keywords = %q, want trimmed email", search.Keywords)
	}
	if search.Filter != "" {
		t.Fatalf("Filter = %q, want empty (query param only)", search.Filter)
	}
}
