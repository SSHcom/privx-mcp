package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePaging_Defaults(t *testing.T) {
	p, errResult := ParsePaging(map[string]any{}, 50)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
	}
	if p.Limit != 50 {
		t.Errorf("limit: got %d want 50", p.Limit)
	}
	if p.Offset != 0 {
		t.Errorf("offset: got %d want 0", p.Offset)
	}
	if p.SortKey != DefaultSortKey {
		t.Errorf("sortKey: got %q want %q", p.SortKey, DefaultSortKey)
	}
	if p.SortDir != DefaultSortDir {
		t.Errorf("sortDir: got %q want %q", p.SortDir, DefaultSortDir)
	}
}

func TestParsePaging_CustomValues(t *testing.T) {
	p, errResult := ParsePaging(map[string]any{
		"limit":   10,
		"offset":  20,
		"sortKey": "common_name",
		"sortDir": "ASC",
	}, 50)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
	}
	if p.Limit != 10 || p.Offset != 20 || p.SortKey != "common_name" || p.SortDir != "ASC" {
		t.Errorf("got %+v", p)
	}
}

func TestParsePaging_SortDirDefaultsWhenKeySet(t *testing.T) {
	p, errResult := ParsePaging(map[string]any{"sortKey": "common_name"}, 50)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
	}
	if p.SortKey != "common_name" {
		t.Errorf("sortKey: got %q", p.SortKey)
	}
	if p.SortDir != DefaultSortDir {
		t.Errorf("sortDir: got %q want %q", p.SortDir, DefaultSortDir)
	}
}

func TestParsePaging_InvalidSortDir(t *testing.T) {
	_, errResult := ParsePaging(map[string]any{"sortDir": "sideways"}, 50)
	if errResult == nil {
		t.Fatal("expected error")
		return
	}
	if !strings.Contains(errResult.Content[0].Text, "sortDir must be ASC or DESC") {
		t.Errorf("got %q", errResult.Content[0].Text)
	}
}

func TestParsePaging_InvalidLimit(t *testing.T) {
	_, errResult := ParsePaging(map[string]any{"limit": 0}, 50)
	if errResult == nil {
		t.Fatal("expected error")
		return
	}
	if !strings.Contains(errResult.Content[0].Text, "limit must be >= 1") {
		t.Errorf("got %q", errResult.Content[0].Text)
	}
}

func TestParsePaging_InvalidOffset(t *testing.T) {
	_, errResult := ParsePaging(map[string]any{"offset": -1}, 50)
	if errResult == nil {
		t.Fatal("expected error")
		return
	}
	if !strings.Contains(errResult.Content[0].Text, "offset must be >= 0") {
		t.Errorf("got %q", errResult.Content[0].Text)
	}
}

func TestPaging_FilterOptions(t *testing.T) {
	p := Paging{Limit: 10, Offset: 5, SortKey: "created", SortDir: "DESC"}
	opts := p.FilterOptions()
	if len(opts) != 2 {
		t.Fatalf("got %d options want 2", len(opts))
	}
}

func TestJSONPage_FirstMiddleFinalOverrun(t *testing.T) {
	items := []map[string]any{{"id": "a"}}
	tests := []struct {
		name           string
		paging         Paging
		count, fetched int
		remaining      float64
		pagesRemaining float64
		nextOffset     any
		wantNextKey    bool
	}{
		{
			name:           "first",
			paging:         Paging{Limit: 10, Offset: 0},
			count:          25,
			fetched:        10,
			remaining:      15,
			pagesRemaining: 2,
			nextOffset:     float64(10),
			wantNextKey:    true,
		},
		{
			name:           "middle",
			paging:         Paging{Limit: 10, Offset: 10},
			count:          25,
			fetched:        10,
			remaining:      5,
			pagesRemaining: 1,
			nextOffset:     float64(20),
			wantNextKey:    true,
		},
		{
			name:           "final",
			paging:         Paging{Limit: 10, Offset: 20},
			count:          25,
			fetched:        5,
			remaining:      0,
			pagesRemaining: 0,
			nextOffset:     nil,
			wantNextKey:    true,
		},
		{
			name:           "overrun",
			paging:         Paging{Limit: 10, Offset: 30},
			count:          25,
			fetched:        0,
			remaining:      0,
			pagesRemaining: 0,
			nextOffset:     nil,
			wantNextKey:    true,
		},
		{
			name:           "list omits nextOffset",
			paging:         Paging{Limit: 50, Offset: 0},
			count:          3,
			fetched:        3,
			remaining:      0,
			pagesRemaining: 0,
			wantNextKey:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts []PageOption
			if tc.wantNextKey {
				opts = append(opts, WithNextOffset())
			}

			result := JSONPage(tc.paging, items, tc.count, tc.fetched, opts...)
			if result.IsError {
				t.Fatalf("unexpected error: %s", result.Content[0].Text)
			}

			var m map[string]any
			if err := json.Unmarshal([]byte(result.Content[0].Text), &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if m["count"].(float64) != float64(tc.count) {
				t.Errorf("count = %v", m["count"])
			}
			if m["limit"].(float64) != float64(tc.paging.Limit) {
				t.Errorf("limit = %v", m["limit"])
			}
			if m["offset"].(float64) != float64(tc.paging.Offset) {
				t.Errorf("offset = %v", m["offset"])
			}
			if m["returned"].(float64) != float64(tc.fetched) {
				t.Errorf("returned = %v", m["returned"])
			}
			if m["remaining"].(float64) != tc.remaining {
				t.Errorf("remaining = %v, want %v", m["remaining"], tc.remaining)
			}
			if m["pagesRemaining"].(float64) != tc.pagesRemaining {
				t.Errorf("pagesRemaining = %v, want %v", m["pagesRemaining"], tc.pagesRemaining)
			}

			gotNext, hasNext := m["nextOffset"]
			if hasNext != tc.wantNextKey {
				t.Fatalf("nextOffset present = %v, want %v", hasNext, tc.wantNextKey)
			}
			if tc.wantNextKey && gotNext != tc.nextOffset {
				t.Errorf("nextOffset = %v, want %v", gotNext, tc.nextOffset)
			}
		})
	}
}

func TestJSONPage_WithReturnedAndExtra(t *testing.T) {
	paging := Paging{Limit: 50, Offset: 0}
	result := JSONPage(
		paging,
		[]map[string]any{{"id": "u2"}},
		82,
		3,
		WithReturned(1),
		WithNextOffset(),
		WithExtra("filter", "all"),
	)
	if result.IsError {
		t.Fatalf("unexpected error: %s", result.Content[0].Text)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].Text), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["returned"].(float64) != 1 {
		t.Errorf("returned = %v, want 1", m["returned"])
	}
	if m["remaining"].(float64) != 79 {
		t.Errorf("remaining = %v, want 79", m["remaining"])
	}
	if m["nextOffset"].(float64) != 3 {
		t.Errorf("nextOffset = %v, want 3", m["nextOffset"])
	}
	if m["filter"] != "all" {
		t.Errorf("filter = %v", m["filter"])
	}
	items := m["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("len(items) = %d", len(items))
	}
}

func TestJSONPage_EncodeFailure(t *testing.T) {
	result := JSONPage(Paging{Limit: 10}, make(chan int), 1, 1)
	if !result.IsError {
		t.Fatal("expected encode error")
	}
	if result.Content[0].Text != "failed to encode response" {
		t.Errorf("got %q", result.Content[0].Text)
	}
}
