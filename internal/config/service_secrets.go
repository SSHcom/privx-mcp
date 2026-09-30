package config

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ParseServiceSecrets splits "user secret|user secret" into hashed mappings.
// The plaintext is not retained in the result.
func ParseServiceSecrets(raw string) ([]ServiceSecret, error) {
	parts := strings.Split(raw, "|")
	out := make([]ServiceSecret, 0, len(parts))
	seen := map[[32]byte]struct{}{}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("server.service_secrets has an empty mapping")
		}

		username, secret, ok := strings.Cut(part, " ")
		if !ok {
			return nil, fmt.Errorf("server.service_secrets mapping has no space between username and secret")
		}

		username = strings.TrimSpace(username)

		secret = strings.TrimSpace(secret)
		if username == "" || secret == "" {
			return nil, fmt.Errorf("server.service_secrets mapping has an empty username or secret")
		}

		if strings.Contains(username, " ") || strings.Contains(username, "|") {
			return nil, fmt.Errorf("server.service_secrets username %q contains a space or '|'", username)
		}

		if strings.Contains(secret, " ") || strings.Contains(secret, "|") {
			return nil, fmt.Errorf("server.service_secrets secret contains a space or '|'")
		}

		if len(secret) < 32 {
			return nil, fmt.Errorf("server.service_secrets secret is shorter than 32 characters")
		}

		sum := sha256.Sum256([]byte(secret))
		if _, dup := seen[sum]; dup {
			return nil, fmt.Errorf("server.service_secrets contains a repeated secret")
		}

		seen[sum] = struct{}{}
		out = append(out, ServiceSecret{Username: username, Sum: sum})
	}

	return out, nil
}

func applyServiceSecrets(cfg *Config) error {
	raw := cfg.Server.serviceSecretsRaw
	cfg.Server.serviceSecretsRaw = ""

	if raw == "" {
		return nil
	}

	secrets, err := ParseServiceSecrets(raw)
	if err != nil {
		return err
	}

	cfg.Server.ServiceSecrets = secrets

	return nil
}
