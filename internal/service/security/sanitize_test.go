package security

import (
	"strings"
	"testing"
	"unsafe"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "clean ascii", in: "web-server-01", want: "web-server-01"},
		{name: "zero width space removed", in: "de\u200Blete", want: "delete"},
		{name: "bidi override removed", in: "host\u202Ename", want: "hostname"},
		{name: "newlines and tabs kept", in: "line one\nline\ttwo\r\n", want: "line one\nline\ttwo\r\n"},
		{name: "non breaking space removed", in: "you\u00A0must", want: "youmust"},
		{name: "printable unicode kept", in: "käyttäjä", want: "käyttäjä"},
		{name: "control character removed", in: "a\x01b", want: "ab"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Clean ASCII must be returned as the same string header, without copying.
func TestSanitize_CleanASCIINotRewritten(t *testing.T) {
	in := "web-server-01\tcomment\n"
	out := Sanitize(in)

	if unsafe.StringData(out) != unsafe.StringData(in) {
		t.Error("expected clean ASCII string to be returned unchanged, got a copy")
	}
}

func TestSanitize_ThenBlacklisted(t *testing.T) {
	term, found := FindBlacklisted(Sanitize("de\u200Blete this host"))
	if !found || term != "delete" {
		t.Fatalf("expected sanitized text to hit %q, got %q found=%v", "delete", term, found)
	}
}

func TestSanitize_LongUnicodePayload(t *testing.T) {
	in := strings.Repeat("a\u200B", 100)
	if got := Sanitize(in); got != strings.Repeat("a", 100) {
		t.Errorf("expected zero-width runes stripped, got %q", got)
	}
}
