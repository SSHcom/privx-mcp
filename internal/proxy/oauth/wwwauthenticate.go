package oauth

import (
	"strings"
	"unicode"
)

type bearerChallenge struct {
	ResourceMetadata string
	Scope            string
}

func parseBearerChallenges(headers []string) bearerChallenge {
	var out bearerChallenge

	for _, h := range headers {
		ch, ok := parseBearerChallenge(h)
		if !ok {
			continue
		}

		if out.ResourceMetadata == "" && ch.ResourceMetadata != "" {
			out.ResourceMetadata = ch.ResourceMetadata
		}

		if out.Scope == "" && ch.Scope != "" {
			out.Scope = ch.Scope
		}
	}

	return out
}

func parseBearerChallenge(header string) (bearerChallenge, bool) {
	rest, ok := stripToBearer(header)
	if !ok {
		return bearerChallenge{}, false
	}

	params := parseAuthParams(rest)

	return bearerChallenge{
		ResourceMetadata: params["resource_metadata"],
		Scope:            params["scope"],
	}, true
}

func stripToBearer(header string) (string, bool) {
	lower := strings.ToLower(header)
	idx := 0

	for {
		i := strings.Index(lower[idx:], "bearer")
		if i < 0 {
			return "", false
		}

		i += idx
		if isBearerSchemeAt(header, i) {
			return strings.TrimSpace(header[i+len("bearer"):]), true
		}

		idx = i + len("bearer")
	}
}

func isBearerSchemeAt(header string, i int) bool {
	if i > 0 {
		prev := header[i-1]
		if prev != ',' && !unicode.IsSpace(rune(prev)) {
			return false
		}
	}

	end := i + len("bearer")
	if end == len(header) {
		return true
	}

	next := header[end]

	return next == ',' || unicode.IsSpace(rune(next))
}

func parseAuthParams(s string) map[string]string {
	out := make(map[string]string)
	i := 0

	for i < len(s) {
		i = skipSpaceAndComma(s, i)
		if i >= len(s) {
			break
		}

		key, next, ok := readToken(s, i)
		if !ok {
			break
		}

		i = skipSpace(s, next)
		if i >= len(s) || s[i] != '=' {
			break
		}

		i++

		val, next := readAuthValue(s, i)
		i = next
		out[strings.ToLower(key)] = val
	}

	return out
}

func readToken(s string, i int) (string, int, bool) {
	i = skipSpace(s, i)
	if i >= len(s) || !isTokenChar(s[i]) {
		return "", i, false
	}

	j := i + 1
	for j < len(s) && isTokenChar(s[j]) {
		j++
	}

	return s[i:j], j, true
}

func readAuthValue(s string, i int) (string, int) {
	i = skipSpace(s, i)
	if i >= len(s) {
		return "", i
	}

	if s[i] == '"' {
		return readQuoted(s, i)
	}

	j := i
	for j < len(s) && s[j] != ',' {
		j++
	}

	return strings.TrimSpace(s[i:j]), j
}

func readQuoted(s string, i int) (string, int) {
	if i >= len(s) || s[i] != '"' {
		return "", i
	}

	i++

	var b strings.Builder

	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2

			continue
		}

		if c == '"' {
			return b.String(), i + 1
		}

		b.WriteByte(c)

		i++
	}

	return b.String(), i
}

func skipSpace(s string, i int) int {
	for i < len(s) && unicode.IsSpace(rune(s[i])) {
		i++
	}

	return i
}

func skipSpaceAndComma(s string, i int) int {
	for i < len(s) {
		if s[i] == ',' || unicode.IsSpace(rune(s[i])) {
			i++

			continue
		}

		break
	}

	return i
}

func isTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}

	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}

	return false
}
