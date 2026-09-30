package utils

import "strings"

// IsLikelyAddress checks if a value resembles an email address.
func IsLikelyAddress(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}

	local, domain, ok := strings.Cut(trimmed, "@")
	if !ok || local == "" || domain == "" {
		return false
	}

	return strings.Contains(domain, ".")
}
