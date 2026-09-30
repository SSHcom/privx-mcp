package utils

import "testing"

func TestEqualFoldTrimmed(t *testing.T) {
	if !EqualFoldTrimmed("  Alice@example.com ", "alice@EXAMPLE.com") {
		t.Fatal("expected equal strings ignoring trim and case")
	}
}

func TestEqualFoldTrimmed_NotEqual(t *testing.T) {
	if EqualFoldTrimmed("alice", "bob") {
		t.Fatal("expected different strings to not match")
	}
}

func TestTrimLower(t *testing.T) {
	got := TrimLower("  Hosts-View ")
	if got != "hosts-view" {
		t.Fatalf("expected hosts-view, got %q", got)
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "id", []string{"id"}},
		{"csv with spaces", " id , common_name , ", []string{"id", "common_name"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitCSV(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("SplitCSV(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("SplitCSV(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestMergeUnique(t *testing.T) {
	got := MergeUnique([]string{"a", "b"}, []string{"b", "c", "d"})
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("MergeUnique = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("MergeUnique = %v, want %v", got, want)
		}
	}
	got = MergeUnique(nil, []string{"x", "x"})
	if len(got) != 1 || got[0] != "x" {
		t.Fatalf("MergeUnique dedup = %v, want [x]", got)
	}
	got = MergeUnique([]string{"a"}, nil)
	if len(got) != 1 || got[0] != "a" {
		t.Fatalf("MergeUnique nil extras = %v, want [a]", got)
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    []string
		wantErr bool
	}{
		{"nil", nil, nil, true},
		{"non-array", "x", nil, true},
		{"happy", []any{"a", "b"}, []string{"a", "b"}, false},
		{"empty element", []any{"a", ""}, nil, true},
		{"non-string element", []any{"a", 1}, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ToStringSlice(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !equalStrings(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
