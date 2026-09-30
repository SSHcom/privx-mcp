package connections

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Paths removed from raw connection payloads. Compact views do not include these nests.
// This is the Hide subset only; the wider host and user redactors are not applied here.
var sensitiveConnectionPaths = []string{
	"target_host_data.host_certificate_raw",
	"target_host_data.ssh_host_public_keys[].key",
	"target_host_data.ssh_host_public_keys[].fingerprint",
	"target_host_data.principals[].passphrase",
	"target_host_data.services[].db.tls_certificate_trust_anchors",
	"user_data.mfa.seed",
}

// FormatConnection projects a Connection into the compact default view.
// Nested objects are flattened to human-readable values.
func FormatConnection(conn connectionmanager.Connection) map[string]any {
	return map[string]any{
		"id":                    conn.ID,
		"type":                  conn.Type,
		"mode":                  conn.Mode,
		"status":                conn.Status,
		"user":                  conn.User.DisplayName,
		"target_host":           conn.TargetHost.CommonName,
		"target_host_address":   conn.TargetHostAddress,
		"target_host_account":   conn.TargetHostAccount,
		"authentication_method": conn.AuthMethod,
		"target_host_roles":     extractRoleNames(conn.TargetHostRoles),
		"remote_address":        conn.RemoteAddress,
		"connected":             conn.Connected,
		"disconnected":          conn.Disconnected,
		"duration":              conn.Duration,
		"bytes_in":              conn.BytesIn,
		"bytes_out":             conn.BytesOut,
		"audit_enabled":         conn.AuditEnabled,
	}
}

// FormatConnectionItems converts a slice of connections to compact maps.
// When raw is true, returns full unfiltered JSON maps instead.
func FormatConnectionItems(items []connectionmanager.Connection, raw bool) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if raw {
			out = append(out, redactRawConnection(utils.ToJSONMap(item)))
		} else {
			out = append(out, FormatConnection(item))
		}
	}

	return out
}

// FormatSingleConnection converts a single connection to a map.
// When raw is true, returns the full unfiltered JSON map.
func FormatSingleConnection(conn *connectionmanager.Connection, raw bool) map[string]any {
	if raw {
		return redactRawConnection(utils.ToJSONMap(conn))
	}

	return FormatConnection(*conn)
}

func redactRawConnection(m map[string]any) map[string]any {
	common.DeletePaths(m, sensitiveConnectionPaths...)
	common.DropNamedAttributes(m, "user_data.attributes", "windows_sid")

	return m
}

// extractRoleNames extracts just the role names from a slice of ConnectionRole.
func extractRoleNames(roles []connectionmanager.ConnectionRole) []string {
	if len(roles) == 0 {
		return []string{}
	}
	// Deduplicate role names (API sometimes returns duplicates).
	seen := make(map[string]struct{}, len(roles))

	names := make([]string, 0, len(roles))
	for _, r := range roles {
		if r.Name == "" {
			continue
		}

		if _, ok := seen[r.Name]; ok {
			continue
		}

		seen[r.Name] = struct{}{}
		names = append(names, r.Name)
	}

	return names
}
