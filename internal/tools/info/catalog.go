package info

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed context/*
var contextFS embed.FS

//go:embed resources/*
var resourceFS embed.FS

// contextKeyAll selects every context topic when passed in the context array.
const contextKeyAll = "all"

// contextKeyAvailableRoles is a live (non-markdown) context loaded from PrivX.
const contextKeyAvailableRoles = "available-roles"

// contextFiles maps public context keys to embedded markdown paths.
var contextFiles = map[string]string{
	"access-groups":   "context/access-groups.md",
	"api-targets":     "context/api-targets.md",
	"audit-events":    "context/audit-events.md",
	"connection":      "context/connection.md",
	"hosts":           "context/hosts-and-connections.md",
	"network-targets": "context/network-targets.md",
	"users-and-roles": "context/users-and-roles.md",
	"whitelists":      "context/whitelists.md",
}

// liveContextKeys are context topics fetched at request time rather than embedded.
var liveContextKeys = []string{contextKeyAvailableRoles}

// resourceFiles maps public resource keys to embedded JSON paths.
var resourceFiles = map[string]string{
	"access-group":      "resources/access-group.json",
	"api-target":        "resources/api-target.json",
	"audit-event":       "resources/audit-event.json",
	"audit-event-codes": "resources/audit-event-codes.json",
	"connection":        "resources/connection.json",
	"host":              "resources/host.json",
	"network-target":    "resources/network-target.json",
	"request (access)":  "resources/request.json",
	"role":              "resources/role.json",
	"role-member":       "resources/role-member.json",
	"user":              "resources/user.json",
	"whitelist":         "resources/whitelist.json",
	// monitor status
	"components-status": "resources/components-status.json",
	"instance-status":   "resources/instance-status.json",
}

func contextKeys() []string {
	keys := make([]string, 0, len(contextFiles)+len(liveContextKeys))
	for k := range contextFiles {
		keys = append(keys, k)
	}

	keys = append(keys, liveContextKeys...)
	sort.Strings(keys)

	return keys
}

func isLiveContextKey(key string) bool {
	for _, live := range liveContextKeys {
		if live == key {
			return true
		}
	}

	return false
}

// contextEnumKeys returns schema enum values for the context parameter (includes "all").
func contextEnumKeys() []string {
	keys := contextKeys()
	out := make([]string, 0, len(keys)+1)
	out = append(out, contextKeyAll)
	out = append(out, keys...)

	return out
}

func resourceKeys() []string {
	return sortedKeys(resourceFiles)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

func resolveContextKeys(keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	for _, key := range keys {
		if key == contextKeyAll {
			return contextKeys(), nil
		}
	}

	for _, key := range keys {
		if _, ok := contextFiles[key]; ok {
			continue
		}

		if isLiveContextKey(key) {
			continue
		}

		return nil, fmt.Errorf("unknown context key %q; allowed: %s", key, strings.Join(contextEnumKeys(), ", "))
	}

	return keys, nil
}

func loadContext(keys []string) (map[string]any, error) {
	resolved, err := resolveContextKeys(keys)
	if err != nil {
		return nil, err
	}

	out := make(map[string]any, len(resolved))
	for _, key := range resolved {
		path, ok := contextFiles[key]
		if !ok {
			continue
		}

		data, err := contextFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load context %q: %w", key, err)
		}

		out[key] = string(data)
	}

	return out, nil
}

func resolvedContains(keys []string, want string) bool {
	resolved, err := resolveContextKeys(keys)
	if err != nil {
		return false
	}

	for _, key := range resolved {
		if key == want {
			return true
		}
	}

	return false
}

func loadResources(keys []string) (map[string]any, error) {
	out := make(map[string]any, len(keys))
	for _, key := range keys {
		path, ok := resourceFiles[key]
		if !ok {
			return nil, fmt.Errorf("unknown resources key %q; allowed: %s", key, strings.Join(resourceKeys(), ", "))
		}

		data, err := resourceFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load resource %q: %w", key, err)
		}

		var obj any
		if err := json.Unmarshal(data, &obj); err != nil {
			return nil, fmt.Errorf("failed to parse resource %q: %w", key, err)
		}

		out[key] = obj
	}

	return out, nil
}
