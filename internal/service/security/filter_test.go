package security

import "testing"

func TestFilter_Redact(t *testing.T) {
	filter := NewFilter([]string{"sudo", "sh", "Ignore"})

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "full word", in: "run sudo now", want: "run [redacted] now"},
		{name: "substring kept", in: "ssh into the host", want: "ssh into the host"},
		{name: "inflection kept", in: "the host was deleted", want: "the host was deleted"},
		{name: "case fold", in: "SUDO", want: "[redacted]"},
		{name: "configured case", in: "please Ignore this", want: "please [redacted] this"},
		{name: "several matches", in: "sh and sudo", want: "[redacted] and [redacted]"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := filter.Redact(tc.in); got != tc.want {
				t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFilter_EmptyIsNoop(t *testing.T) {
	for _, terms := range [][]string{nil, {}, {"", "  "}} {
		filter := NewFilter(terms)
		if got := filter.Redact("sudo sh"); got != "sudo sh" {
			t.Errorf("NewFilter(%q) redacted %q", terms, got)
		}
	}
}

func TestFilter_QuotesMeta(t *testing.T) {
	filter := NewFilter([]string{"a.b"})
	if got := filter.Redact("a.b and axb"); got != "[redacted] and axb" {
		t.Errorf("got %q", got)
	}
}
