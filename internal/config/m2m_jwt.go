package config

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ParseM2MJWTIdentityMapper splits "claim value user|claim value user" into mappings.
// claim is preferred_username or email. Each record is exactly three fields.
func ParseM2MJWTIdentityMapper(raw string) ([]M2MJWTIdentity, error) {
	parts := strings.Split(raw, "|")
	out := make([]M2MJWTIdentity, 0, len(parts))
	seen := map[string]struct{}{}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("server.m2m_jwt_identity_mapper has an empty record")
		}

		fields := strings.Split(part, " ")
		if len(fields) != 3 {
			return nil, fmt.Errorf("server.m2m_jwt_identity_mapper record must be claim, value, and username")
		}

		claim, value, username := fields[0], fields[1], fields[2]
		if claim == "" || value == "" || username == "" {
			return nil, fmt.Errorf("server.m2m_jwt_identity_mapper has an empty field")
		}

		if claim != "preferred_username" && claim != "email" {
			return nil, fmt.Errorf("server.m2m_jwt_identity_mapper claim must be preferred_username or email")
		}

		key := claim + "\x00" + value
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("server.m2m_jwt_identity_mapper contains a repeated claim and value")
		}

		seen[key] = struct{}{}
		out = append(out, M2MJWTIdentity{Claim: claim, Value: value, Username: username})
	}

	return out, nil
}

func applyM2MJWT(cfg *Config) error {
	rawKey := cfg.Server.m2mJWTKeyRaw
	rawMapper := cfg.Server.m2mJWTIdentityMapperRaw
	cfg.Server.m2mJWTKeyRaw = ""
	cfg.Server.m2mJWTIdentityMapperRaw = ""

	if rawKey != "" {
		if len(rawKey) < 12 {
			return fmt.Errorf("server.m2m_jwt_key is shorter than 12 characters")
		}

		cfg.Server.M2MJWTKey = sha256.Sum256([]byte(rawKey))
		cfg.Server.M2MJWTKeySet = true
	}

	if rawMapper == "" {
		return nil
	}

	rows, err := ParseM2MJWTIdentityMapper(rawMapper)
	if err != nil {
		return err
	}

	cfg.Server.M2MJWTIdentityMapper = rows

	return nil
}
