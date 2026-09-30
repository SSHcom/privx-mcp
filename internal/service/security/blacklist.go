package security

import (
	"fmt"
	"regexp"
	"strings"
)

// partialTerms match anywhere in a value, so inflections such as "deleted" or
// "granted" are caught as well. They are long enough not to collide with
// ordinary PrivX identifiers.
var partialTerms = []string{
	"insert", "alter", "edit", "delete", "remove", "truncate",
	"schema", "database", "grant", "elevate", "revoke", "replace",
	"exec", "execute", "eval", "spawn", "sudo", "chmod",
	"chown", "curl", "wget", "fetch", "ping", "nslookup",
	"ignore", "override", "bypass", "forget", "you must",
}

// fullWordTerms are short or high-collision tokens that would produce constant
// false positives as substrings ("sh" in "ssh", "run" in "running", "cmd" in
// "command", "sh" in names like "nashville"), so they only match as whole words.
var fullWordTerms = []string{
	"sh", "cmd", "run", "dns", "root", "stop", "hash",
}

// fullWordPattern matches fullWordTerms on an already lowercased value.
var fullWordPattern = regexp.MustCompile(`\b(?:` + strings.Join(fullWordTerms, "|") + `)\b`)

// DefaultOverrides lists blacklisted terms permitted in the string values of
// specific JSON object keys. These are fields where a term is a legitimate
// PrivX value rather than an instruction: identifier names (principal, name)
// and short enum keys such as "k" (used in status pairs across hosts,
// components, and similar). Overrides are term-level: other blacklisted
// words in the same value are still rejected. "id" is never overridden.
var DefaultOverrides = map[string][]string{
	"principal": {"root"},
	"name":      {"root"},
	// whitelist_patterns holds SSH command-restriction patterns for the
	// whitelist tools. Command names are legitimate data here, so the
	// command/action terms are allowed. Prompt-injection terms (ignore,
	// override, bypass, forget, you must) are intentionally NOT allowed:
	// they never belong in a command pattern.
	"whitelist_patterns": {
		"insert", "alter", "edit", "delete", "remove", "truncate",
		"schema", "database", "grant", "elevate", "revoke", "replace",
		"exec", "execute", "eval", "spawn", "sudo", "chmod",
		"chown", "curl", "wget", "fetch", "ping", "nslookup",
		"sh", "cmd", "run", "dns", "root", "stop", "hash",
	},
}

var overrideSets = buildOverrideSets(DefaultOverrides)

func buildOverrideSets(overrides map[string][]string) map[string]map[string]struct{} {
	sets := make(map[string]map[string]struct{}, len(overrides))
	for key, terms := range overrides {
		sets[key] = termSet(terms)
	}

	return sets
}

func termSet(terms []string) map[string]struct{} {
	if len(terms) == 0 {
		return nil
	}

	set := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		set[strings.ToLower(term)] = struct{}{}
	}

	return set
}

func allowedFor(key string) map[string]struct{} {
	return overrideSets[key]
}

// FindBlacklisted reports the first blacklisted term in s, comparing
// case-insensitively. Callers pass sanitized strings so that invisible runes
// cannot break a term apart.
func FindBlacklisted(s string) (string, bool) {
	return findBlacklisted(s, nil)
}

// findBlacklisted is FindBlacklisted with an ignore set: terms in allowed are
// skipped and the search continues, so an allowed "root" does not hide a later
// "delete".
func findBlacklisted(s string, allowed map[string]struct{}) (string, bool) {
	lowered := strings.ToLower(s)

	for _, term := range partialTerms {
		if _, skip := allowed[term]; skip {
			continue
		}

		if strings.Contains(lowered, term) {
			return term, true
		}
	}

	for _, match := range fullWordPattern.FindAllString(lowered, -1) {
		if _, skip := allowed[match]; skip {
			continue
		}

		return match, true
	}

	return "", false
}

// InputRejectedMessage is returned to the client when an incoming tool
// parameter carries a blacklisted term. The call is not forwarded to the tool.
func InputRejectedMessage(term string) string {
	return fmt.Sprintf("the word %q cannot be used for security reasons", term)
}

// OutputRejectedMessage is returned to the client instead of a tool payload
// that carries a blacklisted term. None of the payload is revealed, and the
// term is deliberately withheld: naming it would leak a fragment of the very
// data being suppressed. Operators find the term in the server log instead.
func OutputRejectedMessage() string {
	return "data cannot be revealed because it contains a blacklisted word"
}
