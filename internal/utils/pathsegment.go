package utils

import "strings"

// SinglePathSegment reports whether value can be interpolated into one REST
// path segment. An empty value is accepted so callers can treat it as omitted.
// "." and ".." are rejected because url.PathEscape leaves them unchanged, so a
// PrivX URL such as /users/.. still walks up a directory. "/" and "\" are
// rejected because a server or proxy that decodes an escaped separator would
// split the value into more than one segment.
func SinglePathSegment(value string) bool {
	if value == "." || value == ".." {
		return false
	}

	return !strings.ContainsAny(value, `/\`)
}
