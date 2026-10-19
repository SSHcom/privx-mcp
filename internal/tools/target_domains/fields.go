package target_domains

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

type stringField struct {
	key string
	set func(*secretsmanager.TargetDomain, string)
}

type boolField struct {
	key string
	set func(*secretsmanager.TargetDomain, bool)
}

type endpointStringField struct {
	key string
	set func(*secretsmanager.TargetDomainEndpoint, string)
}

type endpointIntField struct {
	key      string
	required bool
	set      func(*secretsmanager.TargetDomainEndpoint, int)
}

type managedAccountBoolField struct {
	key string
	set func(*secretsmanager.ManagedAccount, bool)
}

var targetDomainStringFields = []stringField{
	{key: "name", set: func(d *secretsmanager.TargetDomain, v string) { d.Name = v }},
	{key: "domain_name", set: func(d *secretsmanager.TargetDomain, v string) { d.DomainName = v }},
	{key: "comment", set: func(d *secretsmanager.TargetDomain, v string) { d.Comment = v }},
}

var targetDomainBoolFields = []boolField{
	{key: "enabled", set: func(d *secretsmanager.TargetDomain, v bool) { d.Enabled = v }},
	{key: "periodic_scan", set: func(d *secretsmanager.TargetDomain, v bool) { d.PeriodicScan = v }},
	{key: "auto_onboarding", set: func(d *secretsmanager.TargetDomain, v bool) { d.AutoOnboarding = v }},
}

var endpointStringFields = []endpointStringField{
	{key: "ldap_protocol", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapProtocol = v }},
	{key: "ldap_address", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapAddress = v }},
	{key: "ldap_base_dn", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapBaseDN = v }},
	{key: "ldap_bind_dn", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapBindDN = v }},
	{key: "ldap_bind_password", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapBindPassword = v }},
	{key: "ldap_user_filter", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapUserFilter = v }},
	{
		key: "ldap_root_certificates",
		set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.LdapRootCertificates = v },
	},
	{key: "entra_base_url", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.EntraBaseUrl = v }},
	{key: "entra_tenant_id", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.EntraTenantID = v }},
	{key: "entra_client_id", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.EntraClientID = v }},
	{key: "entra_client_secret", set: func(e *secretsmanager.TargetDomainEndpoint, v string) { e.EntraClientSecret = v }},
}

var endpointIntFields = []endpointIntField{
	{
		key:      "scan_priority",
		required: true,
		set:      func(e *secretsmanager.TargetDomainEndpoint, v int) { e.ScanPriority = v },
	},
	{
		key:      "rotation_priority",
		required: true,
		set:      func(e *secretsmanager.TargetDomainEndpoint, v int) { e.RotationPriority = v },
	},
	{key: "ldap_port", set: func(e *secretsmanager.TargetDomainEndpoint, v int) { e.LdapPort = v }},
	{key: "entra_batch_size", set: func(e *secretsmanager.TargetDomainEndpoint, v int) { e.EntraBatchSize = v }},
	{key: "entra_page_size", set: func(e *secretsmanager.TargetDomainEndpoint, v int) { e.EntraPageSize = v }},
}

// ApplyTargetDomainFields overlays present params onto domain. Absent keys
// are left unchanged. Empty strings are ignored so fetched update values
// stay when the caller omits those fields. A present endpoints array
// replaces EndPoints.
func ApplyTargetDomainFields(domain *secretsmanager.TargetDomain, params map[string]any) error {
	for _, field := range targetDomainStringFields {
		v, ok, err := utils.OverlayString(params, field.key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok && v != "" {
			field.set(domain, v)
		}
	}

	for _, field := range targetDomainBoolFields {
		v, ok, err := utils.OverlayBool(params, field.key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok {
			field.set(domain, v)
		}
	}

	if _, ok := params["periodic_scan_interval"]; ok {
		val, err := utils.IntFromMap(params, "periodic_scan_interval", 0)
		if err != nil {
			return fmt.Errorf("validation error: periodic_scan_interval: %w", err)
		}

		domain.PeriodicScanInterval = val
	}

	policyID, ok, err := utils.OverlayString(params, "auto_onboarding_policy_id")
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if ok && policyID != "" {
		domain.AutoOnboardingPolicy = &secretsmanager.PasswordPolicyHandle{ID: policyID}
	}

	if _, ok := params["endpoints"]; ok {
		endpoints, err := endpointsFromParam(params["endpoints"])
		if err != nil {
			return err
		}

		domain.EndPoints = endpoints
	}

	return nil
}

var managedAccountBoolFields = []managedAccountBoolField{
	{key: "enabled", set: func(a *secretsmanager.ManagedAccount, v bool) { a.Enabled = v }},
	{key: "rotation_enabled", set: func(a *secretsmanager.ManagedAccount, v bool) { a.RotationEnabled = v }},
	{key: "explicit_checkout", set: func(a *secretsmanager.ManagedAccount, v bool) { a.ExplicitCheckout = v }},
	{key: "disable_rdp_cert_auth", set: func(a *secretsmanager.ManagedAccount, v bool) { a.DisableRDPCertAuth = v }},
}

// ApplyManagedAccountFields overlays present params onto account. Absent
// keys stay. Empty strings do not clear comment or password_policy_id.
// Directory identity fields are never written.
func ApplyManagedAccountFields(account *secretsmanager.ManagedAccount, params map[string]any) error {
	for _, field := range managedAccountBoolFields {
		v, ok, err := utils.OverlayBool(params, field.key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok {
			field.set(account, v)
		}
	}

	comment, ok, err := utils.OverlayString(params, "comment")
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if ok && comment != "" {
		account.Comment = comment
	}

	policyID, ok, err := utils.OverlayString(params, "password_policy_id")
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if ok && policyID != "" {
		account.PasswordPolicy = &secretsmanager.PasswordPolicyHandle{ID: policyID}
	}

	return nil
}

func endpointsFromParam(raw any) ([]secretsmanager.TargetDomainEndpoint, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("validation error: endpoints must be an array")
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("validation error: endpoints must contain at least one entry")
	}

	endpoints := make([]secretsmanager.TargetDomainEndpoint, 0, len(items))

	seenScanPriority := make(map[int]struct{}, len(items))
	for i, item := range items {
		epMap, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("validation error: endpoints[%d] must be an object", i)
		}

		endpoint, err := endpointFromMap(epMap)
		if err != nil {
			return nil, fmt.Errorf("validation error: endpoints[%d]: %w", i, err)
		}

		if _, dup := seenScanPriority[endpoint.ScanPriority]; dup {
			return nil, fmt.Errorf("validation error: endpoints: duplicate scan_priority %d", endpoint.ScanPriority)
		}

		seenScanPriority[endpoint.ScanPriority] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

func endpointFromMap(params map[string]any) (secretsmanager.TargetDomainEndpoint, error) {
	var endpoint secretsmanager.TargetDomainEndpoint

	endpointType, ok, err := utils.OverlayString(params, "type")
	if err != nil {
		return endpoint, err
	}

	if !ok || endpointType == "" {
		return endpoint, fmt.Errorf("missing required field: type")
	}

	endpoint.Type = endpointType

	for _, field := range endpointIntFields {
		if _, present := params[field.key]; !present {
			if field.required {
				return endpoint, fmt.Errorf("missing required field: %s", field.key)
			}

			continue
		}

		val, err := utils.IntFromMap(params, field.key, 0)
		if err != nil {
			return endpoint, err
		}

		field.set(&endpoint, val)
	}

	for _, field := range endpointStringFields {
		v, ok, err := utils.OverlayString(params, field.key)
		if err != nil {
			return endpoint, err
		}

		if ok && v != "" {
			field.set(&endpoint, v)
		}
	}

	if _, present := params["ldap_skip_strict_cert_check"]; present {
		skip, _, err := utils.OverlayBool(params, "ldap_skip_strict_cert_check")
		if err != nil {
			return endpoint, err
		}

		endpoint.LdapSkipStrictCertCheck = skip
	}

	if raw, present := params["attribute_mapping"]; present {
		mapping, err := stringMapFromParam(raw)
		if err != nil {
			return endpoint, fmt.Errorf("attribute_mapping: %w", err)
		}

		endpoint.AttributeMapping = mapping
	}

	if raw, present := params["entra_group_filter"]; present {
		groups, err := utils.ToStringSlice(raw)
		if err != nil {
			return endpoint, fmt.Errorf("entra_group_filter: %w", err)
		}

		endpoint.EntraGroupFilter = groups
	}

	return endpoint, nil
}

func stringMapFromParam(raw any) (map[string]string, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be an object of strings")
	}

	out := make(map[string]string, len(obj))
	for key, value := range obj {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a string", key)
		}

		out[key] = text
	}

	return out, nil
}
