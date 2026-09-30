package hosts

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// HostServiceItemSchema returns the JSON schema for a single host service
// object (service/address/port). Shared by host-create and host-update so the
// item shape stays identical across the two tools.
func HostServiceItemSchema() *registry.OrderedMap {
	serviceProps := registry.NewOrderedMap().
		Set("service", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": `Service type. Case-sensitive: must be the uppercase PrivX service name (e.g. "SSH", "RDP", "WEB", "VNC", "DB"); lowercase values are rejected by PrivX.`,
		}).
		Set("address", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Service address (DNS name or IP).",
		}).
		Set("port", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Service port.",
		})

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", serviceProps).
		Set("required", []string{"service", "address", "port"}).
		Set("additionalProperties", false)
}

// HostPrincipalItemSchema returns the JSON schema for a single host principal
// object (principal/roles). Shared by host-create and host-update.
func HostPrincipalItemSchema() *registry.OrderedMap {
	principalProps := registry.NewOrderedMap().
		Set("principal", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Principal (account) name on the target host.",
		}).
		Set("roles", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Roles granted to this principal. Each item is a role name or a role UUID. May be empty.",
		})

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", principalProps).
		Set("required", []string{"principal", "roles"}).
		Set("additionalProperties", false)
}

// HostEditProperties returns the OrderedMap of editable host properties used
// by the host-update input schema. It contains every editable scalar/object
// field plus the services and principals arrays (wholesale-replace semantics).
// Sensitive and server-managed fields are intentionally absent; they are
// preserved from the fetched host by the update handler.
func HostEditProperties() *registry.OrderedMap {
	return registry.NewOrderedMap().
		Set("common_name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Host common name. Applied only when the key is present.",
		}).
		Set("addresses", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"minItems":    1,
			"description": "Host addresses (DNS names or IPs). Wholesale-replaces the existing list when present.",
		}).
		Set("services", map[string]any{
			"type":        "array",
			"items":       HostServiceItemSchema(),
			"description": "Services on the host. When present, wholesale-replaces the existing services array; advanced per-service settings not included in this schema reset to PrivX defaults. Omit the array to preserve existing services.",
		}).
		Set("principals", map[string]any{
			"type":        "array",
			"items":       HostPrincipalItemSchema(),
			"description": "Principals on the host. When present, wholesale-replaces the existing principals array; advanced per-principal settings not included in this schema reset to PrivX defaults. Omit the array to preserve existing principals.",
		}).
		Set("organization", map[string]any{
			"type":        "string",
			"description": "Organization.",
		}).
		Set("organizational_unit", map[string]any{
			"type":        "string",
			"description": "Organizational unit.",
		}).
		Set("zone", map[string]any{
			"type":        "string",
			"description": "Network zone.",
		}).
		Set("scope", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Scope tags.",
		}).
		Set("host_type", map[string]any{
			"type":        "string",
			"description": `Host type (e.g. "host", "aws-ec2", "azure-vm", "gcp-instance").`,
		}).
		Set("host_classification", map[string]any{
			"type":        "string",
			"description": "Host classification.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Free-form comment.",
		}).
		Set("contact_address", map[string]any{
			"type":        "string",
			"description": "Contact address.",
		}).
		Set("user_message", map[string]any{
			"type":        "string",
			"description": "Message displayed to users on connection.",
		}).
		Set("distinguished_name", map[string]any{
			"type":        "string",
			"description": "Distinguished name.",
		}).
		Set("external_id", map[string]any{
			"type":        "string",
			"description": "External id (the host's id in an external source).",
		}).
		Set("instance_id", map[string]any{
			"type":        "string",
			"description": "Cloud instance id.",
		}).
		Set("access_group_id", map[string]any{
			"type":        "string",
			"description": "Access group id (UUID).",
		}).
		Set("cloud_provider", map[string]any{
			"type":        "string",
			"description": `Cloud provider (e.g. "aws", "azure", "gcp").`,
		}).
		Set("cloud_provider_region", map[string]any{
			"type":        "string",
			"description": "Cloud provider region (e.g. \"eu-west-1\").",
		}).
		Set("tags", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Tags.",
		}).
		Set("audit_enabled", map[string]any{
			"type":        "boolean",
			"description": "Enable auditing. Applied (including explicit false) only when the key is present.",
		}).
		Set("tofu", map[string]any{
			"type":        "boolean",
			"description": "Trust on first use. Applied (including explicit false) only when the key is present.",
		}).
		Set("toch", map[string]any{
			"type":        "boolean",
			"description": "Trust on changed hostkey. Applied (including explicit false) only when the key is present.",
		}).
		Set("stand_alone_host", map[string]any{
			"type":        "boolean",
			"description": "Stand-alone host flag. Applied (including explicit false) only when the key is present.",
		}).
		Set("session_recording_options", map[string]any{
			"type":                 "object",
			"description":          "Per-feature session-recording toggles. When present, replaces the existing object.",
			"properties":           sessionRecordingOptionsProps(),
			"additionalProperties": false,
		})
}

// sessionRecordingOptionsProps returns just the inner properties map for the
// session_recording_options object, used so the outer schema entry can carry
// the nested properties without re-wrapping type/object.
func sessionRecordingOptionsProps() *registry.OrderedMap {
	return registry.NewOrderedMap().
		Set("disable_clipboard_recording", map[string]any{
			"type":        "boolean",
			"description": "Disable clipboard recording for sessions to this host.",
		}).
		Set("disable_file_transfer_recording", map[string]any{
			"type":        "boolean",
			"description": "Disable file-transfer recording for sessions to this host.",
		})
}
