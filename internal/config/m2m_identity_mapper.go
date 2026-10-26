package config

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ParseM2MIdentityMapper splits "user secret|user secret" into hashed mappings.
// The plaintext is not retained in the result.
func ParseM2MIdentityMapper(raw string) ([]M2MIdentity, error) {
	parts := strings.Split(raw, "|")
	out := make([]M2MIdentity, 0, len(parts))
	seen := map[[32]byte]struct{}{}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("server.m2m_identity_mapper has an empty mapping")
		}

		username, secret, ok := strings.Cut(part, " ")
		if !ok {
			return nil, fmt.Errorf("server.m2m_identity_mapper mapping has no space between username and secret")
		}

		username = strings.TrimSpace(username)

		secret = strings.TrimSpace(secret)
		if username == "" || secret == "" {
			return nil, fmt.Errorf("server.m2m_identity_mapper mapping has an empty username or secret")
		}

		if strings.Contains(username, " ") || strings.Contains(username, "|") {
			return nil, fmt.Errorf("server.m2m_identity_mapper username %q contains a space or '|'", username)
		}

		if strings.Contains(secret, " ") || strings.Contains(secret, "|") {
			return nil, fmt.Errorf("server.m2m_identity_mapper secret contains a space or '|'")
		}

		if len(secret) < 32 {
			return nil, fmt.Errorf("server.m2m_identity_mapper secret is shorter than 32 characters")
		}

		sum := sha256.Sum256([]byte(secret))
		if _, dup := seen[sum]; dup {
			return nil, fmt.Errorf("server.m2m_identity_mapper contains a repeated secret")
		}

		seen[sum] = struct{}{}
		out = append(out, M2MIdentity{Username: username, Sum: sum})
	}

	return out, nil
}

func applyM2MIdentityMapper(cfg *Config) error {
	raw := cfg.Server.m2mIdentityMapperRaw
	cfg.Server.m2mIdentityMapperRaw = ""

	if raw == "" {
		return nil
	}

	mappings, err := ParseM2MIdentityMapper(raw)
	if err != nil {
		return err
	}

	cfg.Server.M2MIdentityMapper = mappings

	return nil
}
