package security

import "fmt"

// PrepareStrings sanitizes the given strings in place and reports the first
// blacklisted term found, ignoring terms in allowed (compared
// case-insensitively). It exists for trusted payloads (see
// registry.ToolResult.Trusted) that still embed individual PrivX-sourced
// strings, which the runtime no longer inspects for them. Pass
// DefaultOverrides["principal"] or DefaultOverrides["name"] for identifier
// fields that have no JSON key context.
func PrepareStrings(allowed []string, values ...*string) (string, bool) {
	set := termSet(allowed)

	for _, value := range values {
		if value == nil {
			continue
		}

		*value = Sanitize(*value)
		if term, found := findBlacklisted(*value, set); found {
			return term, true
		}
	}

	return "", false
}

// Prepare sanitizes every string value reachable from v and reports the first
// blacklisted term found. Only values are inspected; map keys are left alone,
// so a field named "email" or "delete" is never a hit by itself.
//
// String values under keys listed in DefaultOverrides may contain those keys'
// allowed terms (for example "root" on principal and name).
// Nested objects do not inherit a parent key's allowances: roles[].name uses
// the name override, while roles[].comment stays fully blacklisted. String
// arrays inherit the enclosing key's allowances, but roles itself is not an
// overridden key.
//
// Maps and slices are mutated in place and a sanitized string is written back
// only when sanitizing actually changed it. The returned value differs from v
// only when v is a string itself. The walk stops at the first blacklisted term,
// leaving the rest of the tree untouched: a hit means the payload is rejected,
// not delivered.
func Prepare(v any) (any, string, bool) {
	cleaned, hit, found := prepare(v, nil)
	return cleaned, hit.term, found
}

// OmittedItem is a list/search row dropped by PrepareOutput. The runtime
// warns operators with these fields; they are never sent to the MCP client.
type OmittedItem struct {
	ID     string
	HasID  bool
	Key    string
	Value  string
	Term   string
	Record any
}

// PrepareOutput sanitizes v for delivery. When v is a JSON object with a
// top-level "items" array, each element is prepared on its own: a blacklist
// hit drops that element instead of rejecting the payload. Other top-level
// fields are still all-or-nothing. omitted lists the dropped rows (paging
// fields are left unchanged). found is true when a non-item field, or a
// payload without a top-level items array, hits the blacklist.
func PrepareOutput(v any) (cleaned any, omitted []OmittedItem, term string, found bool) {
	root, ok := v.(map[string]any)
	if !ok {
		cleaned, term, found = Prepare(v)
		return cleaned, nil, term, found
	}

	items, ok := root["items"].([]any)
	if !ok {
		cleaned, term, found = Prepare(v)
		return cleaned, nil, term, found
	}

	kept := make([]any, 0, len(items))
	for _, item := range items {
		_, hit, hitFound := prepare(item, nil)
		if hitFound {
			omitted = append(omitted, newOmittedItem(item, hit))
			continue
		}

		kept = append(kept, item)
	}

	root["items"] = kept

	for key, element := range root {
		if key == "items" {
			continue
		}

		clean, hit, hitFound := prepare(element, allowedFor(key))
		if _, isString := element.(string); isString && clean != element {
			root[key] = clean
		}

		if hitFound {
			return root, nil, hit.term, true
		}
	}

	return root, omitted, "", false
}

type prepareHit struct {
	term  string
	key   string
	value string
	found bool
}

func prepare(v any, allowed map[string]struct{}) (any, prepareHit, bool) {
	switch value := v.(type) {
	case string:
		clean := Sanitize(value)

		term, found := findBlacklisted(clean, allowed)
		if found {
			return clean, prepareHit{term: term, value: clean, found: true}, true
		}

		return clean, prepareHit{found: false}, false
	case map[string]any:
		for key, element := range value {
			clean, hit, found := prepare(element, allowedFor(key))
			if _, isString := element.(string); isString && clean != element {
				value[key] = clean
			}

			if found {
				if hit.key == "" {
					hit.key = key
				}

				return value, hit, true
			}
		}
	case []any:
		for i, element := range value {
			clean, hit, found := prepare(element, allowed)
			if _, isString := element.(string); isString && clean != element {
				value[i] = clean
			}

			if found {
				return value, hit, true
			}
		}
	}

	return v, prepareHit{found: false}, false
}

func newOmittedItem(item any, hit prepareHit) OmittedItem {
	if id, ok := itemID(item); ok {
		return OmittedItem{ID: id, HasID: true, Key: hit.key, Value: hit.value, Term: hit.term}
	}

	return OmittedItem{Record: item, Term: hit.term}
}

func itemID(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false
	}

	raw, ok := m["id"]
	if !ok || raw == nil {
		return "", false
	}

	switch id := raw.(type) {
	case string:
		if id == "" {
			return "", false
		}

		return id, true
	default:
		s := fmt.Sprint(id)
		if s == "" {
			return "", false
		}

		return s, true
	}
}
