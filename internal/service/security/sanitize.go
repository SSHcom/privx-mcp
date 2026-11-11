package security

import (
	"strings"
	"unicode"
)

// Sanitize removes runes that can hide text from a human reader while still
// reaching the model: zero-width joiners, bidi and other format characters,
// control characters, non-ASCII spaces such as NBSP, and invisible combining
// marks. Visible accents stay. Newline, carriage return, and tab are kept
// because multi-line fields (host comments and similar) rely on them.
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
// Invisible combining marks are printable to Go, but they have no glyph.
func allowedRune(r rune) bool {
	switch r {
	case '\n', '\r', '\t':
		return true
	}

	return unicode.IsPrint(r) && !invisibleMark(r)
}

// invisibleMark reports combining marks that take no space and draw nothing.
// A visible accent, such as the diaeresis in a decomposed ä, is not one of these.
func invisibleMark(r rune) bool {
	switch {
	case r == '\u034F', r == '\u17B4', r == '\u17B5':
		return true
	case r >= '\u180B' && r <= '\u180F':
		return true
	case r >= '\uFE00' && r <= '\uFE0F':
		return true
	case r >= '\U000E0100' && r <= '\U000E01EF':
		return true
	default:
		return false
	}
}
