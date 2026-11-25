package utils

import "testing"

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		value   string
		pattern string
		want    bool
	}{
		{"host-list", "host-list", true},
		{"host-list", "host-", false},
		{"host-list", "host", false},
		{"host-list-extra", "host-list", false},
		{"host-list", "*-list", true},
		{"user-search", "*-list", false},
		{"host-list-x", "*-list", false},
		{"host-list", "host-*", true},
		{"user-list", "host-*", false},
		{"user-secret-get", "*secret*", true},
		{"user-get", "*secret*", false},
		{"access-group-delete", "access-*-delete", true},
		{"access-group-get", "access-*-delete", false},
		{"a-b-c-d", "*-*-*-*", true},
		{"a-b-c", "*-*-*-*", false},
		{"abab", "ab*ab", true},
		{"aba", "ab*ab", false},
		{"anything", "*", false},
		{"", "*", false},
		{"ab", "ab*", false},
		{"ab-x", "*-x", false},
		{"ab-x", "**-x", false},
		{"a-li", "*-li", true},
		{"ab", "ab", true},
		{"Host-list", "host-*", false},
	}

	for _, tt := range tests {
		if got := MatchWildcard(tt.value, tt.pattern); got != tt.want {
			t.Errorf("MatchWildcard(%q, %q) = %v, want %v", tt.value, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchAnyWildcard(t *testing.T) {
	patterns := []string{"*-delete", "mcp-info"}

	if !MatchAnyWildcard("host-delete", patterns) {
		t.Error("expected host-delete to match *-delete")
	}
	if !MatchAnyWildcard("mcp-info", patterns) {
		t.Error("expected mcp-info to match exactly")
	}
	if MatchAnyWildcard("host-list", patterns) {
		t.Error("expected host-list not to match")
	}
	if MatchAnyWildcard("host-delete", nil) {
		t.Error("expected no match with no patterns")
	}
}

func TestUsableWildcards(t *testing.T) {
	got := UsableWildcards([]string{"*", "**", "*-x", "ab*", "abc*", "*-list", "ab"})
	want := []string{"abc*", "*-list", "ab"}

	if len(got) != len(want) {
		t.Fatalf("UsableWildcards = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("UsableWildcards = %v, want %v", got, want)
		}
	}
}
