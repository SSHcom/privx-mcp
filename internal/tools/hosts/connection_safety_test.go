package hosts

import (
	"testing"
)

func TestParseConnectionTime(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"", false},
		{"not-a-time", false},
		{"2024-01-15T10:30:00Z", true},
		{"2024-01-15T10:30:00.123456789Z", true},
		{"2024-01-15T10:30:00.999999Z", true},
	}
	for _, tc := range tests {
		_, ok := parseConnectionTime(tc.in)
		if ok != tc.ok {
			t.Errorf("parseConnectionTime(%q) ok = %v, want %v", tc.in, ok, tc.ok)
		}
	}
}
