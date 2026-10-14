package target_domains

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// DomainFieldProperties returns the shared target-domain create and update
// properties. Update adds id in front of this set.
func DomainFieldProperties() *registry.OrderedMap {
	return registry.NewOrderedMap().
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Target domain name.",
		}).
		Set("domain_name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "DNS name of the AD/Entra domain.",
		}).
		Set("enabled", map[string]any{
			"type":        "boolean",
			"description": "Whether the target domain is enabled.",
		}).
		Set("periodic_scan", map[string]any{
			"type":        "boolean",
			"description": "Whether PrivX scans the domain on an interval.",
		}).
		Set("periodic_scan_interval", map[string]any{
			"type":        "integer",
			"description": "Scan interval integer.",
		}).
		Set("auto_onboarding", map[string]any{
			"type":        "boolean",
			"description": "Whether scanned accounts are onboarded automatically.",
		}).
		Set("auto_onboarding_policy_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Password policy id used for auto-onboarding. Omit to leave the current policy unchanged.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Comment stored on the target domain.",
		}).
		Set("endpoints", map[string]any{
			"type":     "array",
			"minItems": 1,
			"items":    endpointItemSchema(),
			"description": "AD/LDAP or Entra endpoints. Scan priorities must be unique among the domain's endpoints. " +
				"At least one endpoint is used for password rotation.",
		})
}

func endpointItemSchema() *registry.OrderedMap {
	properties := registry.NewOrderedMap().
		Set("type", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Endpoint kind (AD/LDAP or Entra).",
		}).
		Set("scan_priority", map[string]any{
			"type":        "integer",
			"description": "Scan priority. Must be unique among this domain's endpoints.",
		}).
		Set("rotation_priority", map[string]any{
			"type": "integer",
			"description": "API integer for rotation priority. " +
				"The product UI labels endpoints Primary, Secondary, and Disabled. " +
				"This value is that API integer.",
		}).
		Set("attribute_mapping", map[string]any{
			"type":                 "object",
			"additionalProperties": map[string]any{"type": "string"},
			"description":          "Directory attribute mapping.",
		}).
		Set("ldap_protocol", map[string]any{
			"type":        "string",
			"description": "LDAP protocol, such as STARTTLS.",
		}).
		Set("ldap_address", map[string]any{
			"type":        "string",
			"description": "LDAP server address.",
		}).
		Set("ldap_port", map[string]any{
			"type":        "integer",
			"description": "LDAP server port.",
		}).
		Set("ldap_base_dn", map[string]any{
			"type":        "string",
			"description": "LDAP base DN.",
		}).
		Set("ldap_bind_dn", map[string]any{
			"type":        "string",
			"description": "LDAP bind DN.",
		}).
		Set("ldap_bind_password", map[string]any{
			"type": "string",
			"description": "LDAP bind password. Required when creating an AD/LDAP endpoint; " +
				"PrivX rejects the create when it is missing. " +
				"The value is stored and will not be returned by " +
				"target-domain-list or target-domain-get.",
		}).
		Set("ldap_user_filter", map[string]any{
			"type":        "string",
			"description": "LDAP user filter.",
		}).
		Set("ldap_root_certificates", map[string]any{
			"type":        "string",
			"description": "PEM root certificates for the LDAP endpoint.",
		}).
		Set("ldap_skip_strict_cert_check", map[string]any{
			"type":        "boolean",
			"description": "Skip strict certificate checking for the LDAP endpoint.",
		}).
		Set("entra_base_url", map[string]any{
			"type":        "string",
			"description": "Entra base URL.",
		}).
		Set("entra_tenant_id", map[string]any{
			"type":        "string",
			"description": "Entra tenant id.",
		}).
		Set("entra_client_id", map[string]any{
			"type":        "string",
			"description": "Entra application client id.",
		}).
		Set("entra_client_secret", map[string]any{
			"type": "string",
			"description": "Entra client secret. The value is stored and will not be returned by " +
				"target-domain-list or target-domain-get.",
		}).
		Set("entra_batch_size", map[string]any{
			"type":        "integer",
			"description": "Entra batch size.",
		}).
		Set("entra_page_size", map[string]any{
			"type":        "integer",
			"description": "Entra page size.",
		}).
		Set("entra_group_filter", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Entra group filter.",
		})

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"type", "scan_priority", "rotation_priority"}).
		Set("additionalProperties", false)
}
