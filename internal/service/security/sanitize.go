package security

import (
	"strings"
	"unicode"
)

// Sanitize removes runes that can hide text from a human reader while still
// reaching the model: zero-width joiners, bidi and other format characters,
// control characters, and non-ASCII spaces such as NBSP. Newline, carriage
// return, and tab are kept because multi-line fields (host comments and
// similar) rely on them.
//
// Strings that consist only of printable ASCII and those three whitespace
// characters are returned unchanged, without allocating.
func Sanitize(s string) string {
	if isCleanASCII(s) {
		return s
	}

	return strings.Map(func(r rune) rune {
		if allowedRune(r) {
			return r
		}

		return -1
	}, s)
}

func isCleanASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x20 && b <= 0x7E {
			continue
		}

		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}

		return false
	}

	return true
}

// allowedRune keeps anything unicode.IsPrint accepts (letters, marks,
// punctuation, symbols, and ASCII space; Cf, bidi controls, and exotic spaces
// are already excluded) plus the three whitespace characters IsPrint rejects.
func allowedRune(r rune) bool {
	switch r {
	case '\n', '\r', '\t':
		return true
	}

	return unicode.IsPrint(r)
}
