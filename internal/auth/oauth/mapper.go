package oauth

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// IdentityMapper transforms IdP claims to a PrivX username.
type IdentityMapper interface {
	Map(claims *IdentityClaims) (string, error)
}

// identityMapper implements IdentityMapper with configurable claim field and mapping rule.
type identityMapper struct {
	claimField  string
	mappingRule string
}

// NewIdentityMapper creates an IdentityMapper that reads the specified claim field
// and applies the given mapping rule ("strip-domain" or "as-is").
func NewIdentityMapper(claimField, mappingRule string) IdentityMapper {
	return &identityMapper{
		claimField:  claimField,
		mappingRule: mappingRule,
	}
}

// Map extracts the configured claim from identity claims and applies the mapping rule.
func (m *identityMapper) Map(claims *IdentityClaims) (string, error) {
	logging.Debug(
		"mapping identity claim to PrivX username",
		"claim_field", m.claimField,
		"mapping_rule", m.mappingRule,
	)

	value, err := m.extractClaim(claims)
	if err != nil {
		return "", err
	}

	if value == "" {
		logging.Info(
			"configured identity claim not found in token",
			"claim_field", m.claimField,
			"mapping_rule", m.mappingRule,
			"available_claims", topLevelClaimKeys(claims.RawClaims),
		)

		return "", fmt.Errorf("identity claim '%s' not found in token", m.claimField)
	}

	switch m.mappingRule {
	case "strip-domain":
		mapped := stripDomain(value)
		logging.Debug(
			"identity claim mapped",
			"claim_field", m.claimField,
			"claim_value", value,
			"mapped_username", mapped,
			"mapping_rule", m.mappingRule,
		)

		return mapped, nil
	case "as-is":
		logging.Debug(
			"identity claim mapped",
			"claim_field", m.claimField,
			"claim_value", value,
			"mapped_username", value,
			"mapping_rule", m.mappingRule,
		)

		return value, nil
	default:
		logging.Debug(
			"identity claim mapped",
			"claim_field", m.claimField,
			"claim_value", value,
			"mapped_username", value,
			"mapping_rule", m.mappingRule,
		)

		return value, nil
	}
}

// extractClaim reads the configured claim field from OIDC identity claims.
func (m *identityMapper) extractClaim(claims *IdentityClaims) (string, error) {
	if claims == nil {
		return "", fmt.Errorf("claims are required")
	}

	if strings.TrimSpace(m.claimField) == "" {
		return "", fmt.Errorf("identity claim field is required")
	}

	if claims.RawClaims == nil {
		return "", fmt.Errorf("raw token claims are required")
	}

	rawValue, ok := claimByPath(claims.RawClaims, m.claimField)
	if !ok {
		return "", nil
	}

	stringValue, ok := rawValue.(string)
	if !ok {
		return "", fmt.Errorf("identity claim '%s' must be a string, got %T", m.claimField, rawValue)
	}

	return stringValue, nil
}

// stripDomain extracts the local part before '@' from an email-like string.
// If no '@' is present, the string is returned unchanged.
func stripDomain(s string) string {
	if idx := strings.IndexByte(s, '@'); idx >= 0 {
		return s[:idx]
	}

	return s
}

func claimByPath(claims map[string]any, path string) (any, bool) {
	segments := strings.Split(path, ".")
	current := any(claims)

	for _, segment := range segments {
		if segment == "" {
			return nil, false
		}

		name, indexes, err := parsePathSegment(segment)
		if err != nil {
			return nil, false
		}

		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		current, ok = obj[name]
		if !ok {
			return nil, false
		}

		for _, idx := range indexes {
			items, ok := current.([]any)
			if !ok {
				return nil, false
			}

			if idx < 0 || idx >= len(items) {
				return nil, false
			}

			current = items[idx]
		}
	}

	return current, true
}

func parsePathSegment(segment string) (string, []int, error) {
	base, rest, found := strings.Cut(segment, "[")
	if !found {
		return segment, nil, nil
	}

	if base == "" {
		return "", nil, fmt.Errorf("empty claim path segment")
	}

	indexes := make([]int, 0, 1)

	remaining := "[" + rest
	for remaining != "" {
		if remaining[0] != '[' {
			return "", nil, fmt.Errorf("invalid claim path segment")
		}

		end := strings.IndexByte(remaining, ']')
		if end <= 1 {
			return "", nil, fmt.Errorf("invalid claim path index")
		}

		indexValue := remaining[1:end]

		index, err := strconv.Atoi(indexValue)
		if err != nil {
			return "", nil, fmt.Errorf("invalid claim path index")
		}

		indexes = append(indexes, index)
		remaining = remaining[end+1:]
	}

	return base, indexes, nil
}

func topLevelClaimKeys(claims map[string]any) []string {
	if len(claims) == 0 {
		return nil
	}

	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
