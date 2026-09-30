package network_targets

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// DestinationItemSchema returns the JSON schema for a single destination
// object (selector + optional nat). Shared by network-target-create and
// network-target-update.
func DestinationItemSchema() *registry.OrderedMap {
	ipProps := registry.NewOrderedMap().
		Set("start", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Start of the destination IP range. Also used as end when end is omitted.",
		}).
		Set("end", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "End of the destination IP range. Defaults to start when omitted.",
		})

	portProps := registry.NewOrderedMap().
		Set("start", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"maximum":     65535,
			"description": "Start of the destination port range. Also used as end when end is omitted.",
		}).
		Set("end", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"maximum":     65535,
			"description": "End of the destination port range. Defaults to start when omitted.",
		})

	selectorProps := registry.NewOrderedMap().
		Set("ip", registry.NewOrderedMap().
			Set("type", "object").
			Set("properties", ipProps).
			Set("required", []string{"start"}).
			Set("additionalProperties", false)).
		Set("proto", map[string]any{
			"type":        "string",
			"description": `Protocol (e.g. "TCP", "UDP", "All"). When "All", port and nat must not be set.`,
		}).
		Set("port", registry.NewOrderedMap().
			Set("type", "object").
			Set("properties", portProps).
			Set("required", []string{"start"}).
			Set("additionalProperties", false).
			Set("description", `Port range. Not allowed when proto is "All".`))

	natProps := registry.NewOrderedMap().
		Set("addr", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "NAT address (IP or extender/IP form).",
		}).
		Set("port", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"maximum":     65535,
			"description": "Optional NAT port.",
		})

	dstProps := registry.NewOrderedMap().
		Set("selector", registry.NewOrderedMap().
			Set("type", "object").
			Set("properties", selectorProps).
			Set("required", []string{"ip"}).
			Set("additionalProperties", false)).
		Set("nat", registry.NewOrderedMap().
			Set("type", "object").
			Set("properties", natProps).
			Set("required", []string{"addr"}).
			Set("additionalProperties", false).
			Set("description", `NAT parameters. Not allowed when proto is "All".`))

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", dstProps).
		Set("required", []string{"selector"}).
		Set("additionalProperties", false)
}

// RoleItemSchema returns the JSON schema for a single role handle object.
// Shared by network-target-create and network-target-update.
func RoleItemSchema() *registry.OrderedMap {
	roleProps := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Role id (UUID).",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"description": "Optional role name (informational; id is authoritative).",
		})

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", roleProps).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)
}

// NetworkTargetCreateProperties returns the create input properties, including
// the required name field.
func NetworkTargetCreateProperties() *registry.OrderedMap {
	return networkTargetBodyProperties(true)
}

// NetworkTargetEditProperties returns editable update properties used by
// network-target-update (excluding the required id).
func NetworkTargetEditProperties() *registry.OrderedMap {
	return networkTargetBodyProperties(false)
}

func networkTargetBodyProperties(forCreate bool) *registry.OrderedMap {
	nameDesc := "Network target name."
	dstDesc := "Destination selectors (and optional NAT). When present, wholesale-replaces the existing dst array."
	rolesDesc := "Roles granted access. Each item requires id. When present, wholesale-replaces the existing roles array."

	if forCreate {
		dstDesc = "Destination selectors (and optional NAT). May be empty."
		rolesDesc = "Roles granted access. Each item requires id. May be empty."
	} else {
		nameDesc = "Network target name. Applied only when the key is present."
	}

	return registry.NewOrderedMap().
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": nameDesc,
		}).
		Set("dst", map[string]any{
			"type":        "array",
			"items":       DestinationItemSchema(),
			"description": dstDesc,
		}).
		Set("roles", map[string]any{
			"type":        "array",
			"items":       RoleItemSchema(),
			"description": rolesDesc,
		}).
		Set("tags", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Tags. When present on update, wholesale-replaces the existing list.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Free-form comment.",
		}).
		Set("user_instructions", map[string]any{
			"type":        "string",
			"description": "Instructions shown to users for this network target.",
		}).
		Set("src_nat", map[string]any{
			"type":        "boolean",
			"description": "Enable source NAT. Applied (including explicit false) only when the key is present.",
		}).
		Set("static_config", map[string]any{
			"type": "string",
			"description": `Static configuration as a JSON string. Must be empty/omitted when integration_type is None. ` +
				`For NQX it must be exactly {"type":"l3rules"|"tunnel"|"combo","source_id":"...","source_name":"..."}. ` +
				`For GENERIC any valid JSON is accepted.`,
		}).
		Set("exclusive_access", map[string]any{
			"type":        "boolean",
			"description": "Exclusive access flag. Applied (including explicit false) only when the key is present.",
		}).
		Set("integration_type", map[string]any{
			"type":        "string",
			"enum":        []string{"GENERIC", "NQX"},
			"description": `Integration type: "GENERIC" or "NQX". Omit for None (no integration). When None, static_config is empty. NQX requires a valid static_config object.`,
		})
}
