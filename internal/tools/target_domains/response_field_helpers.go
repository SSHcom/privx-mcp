package target_domains

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default field sets always returned by target-domain-list when callers do
// not request raw output. Endpoints are included only when fields names them.
var (
	DefaultTargetDomainFields = []string{
		"id",
		"name",
		"domain_name",
		"enabled",
		"periodic_scan",
		"scan_status",
		"last_scanned",
		"auto_onboarding",
		"comment",
	}
	DefaultEndpointFields = []string{
		"type",
		"scan_priority",
		"rotation_priority",
		"ldap_address",
		"ldap_port",
		"ldap_base_dn",
		"entra_tenant_id",
	}
	DefaultManagedAccountFields = []string{
		"id",
		"username",
		"full_name",
		"email",
		"enabled",
		"rotation_enabled",
		"explicit_checkout",
		"state",
		"password_policy",
		"comment",
		"locked",
	}
	DefaultScannedAccountFields = []string{
		"id",
		"username",
		"full_name",
		"email",
		"state",
		"ignored",
	}

	handleFields          = []string{"id", "name", "deleted"}
	rotationHistoryFields = []string{"version", "rotated", "trigger", "status"}
	checkoutFields        = []string{
		"id",
		"user_id",
		"expires",
		"created",
		"explicit_checkout",
		"username",
	}

	// Sensitive paths always stripped from target-domain and managed-account
	// payloads, including raw output and explicit field requests.
	sensitiveTargetDomainPaths = []string{
		"endpoints[].ldap_bind_password",
		"endpoints[].entra_client_secret",
		"checkouts[].secrets",
	}
)

// Projection is the target-domain and endpoint field sets for list.
type Projection struct {
	Root      []string
	Endpoints []string
}

// ProjectionFromParams merges default target-domain field sets with optional CSV extras.
func ProjectionFromParams(params map[string]any) Projection {
	return Projection{
		Root:      utils.MergeUnique(DefaultTargetDomainFields, utils.CSVFromMap(params, "fields")),
		Endpoints: utils.MergeUnique(DefaultEndpointFields, utils.CSVFromMap(params, "endpointFields")),
	}
}

// SelectTargetDomainFields builds a filtered target-domain map containing only
// the requested root fields. The endpoints array is filtered with its own
// field set. Nested objects such as auto_onboarding_policy are copied as
// returned. Unknown field names are skipped.
func SelectTargetDomainFields(domain map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "endpoints":
			out["endpoints"] = common.ProjectArray(domain["endpoints"], p.Endpoints, common.OmitMissing)
		default:
			if value, ok := domain[field]; ok {
				out[field] = value
			}
		}
	}

	return out
}

// RedactSensitiveTargetDomainFields removes bind passwords, Entra client
// secrets, and checkout password versions from a JSON map in place.
func RedactSensitiveTargetDomainFields(domain map[string]any) map[string]any {
	if domain == nil {
		return nil
	}

	common.DeletePaths(domain, sensitiveTargetDomainPaths...)

	return domain
}

// FormatTargetDomain converts a target domain to a JSON map with secrets removed.
func FormatTargetDomain(v any) map[string]any {
	return RedactSensitiveTargetDomainFields(utils.ToJSONMap(v))
}

// FormatTargetDomainItems converts target domains to response maps. When raw
// is false, fields are projected with SelectTargetDomainFields; secrets are
// always redacted.
func FormatTargetDomainItems(items []secretsmanager.TargetDomain, raw bool, p Projection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		domainMap := utils.ToJSONMap(item)
		if !raw {
			domainMap = SelectTargetDomainFields(domainMap, p)
		}

		out = append(out, RedactSensitiveTargetDomainFields(domainMap))
	}

	return out
}

// ManagedAccountProjection is the managed-account field set for list.
type ManagedAccountProjection struct {
	Root []string
}

// ManagedAccountProjectionFromParams merges default managed-account fields with optional CSV extras.
func ManagedAccountProjectionFromParams(params map[string]any) ManagedAccountProjection {
	return ManagedAccountProjection{
		Root: utils.MergeUnique(DefaultManagedAccountFields, utils.CSVFromMap(params, "fields")),
	}
}

// SelectManagedAccountFields builds a filtered managed-account map.
// password_policy and target_domain keep the handle fields. rotation_history
// and checkouts keep their non-secret fields. Unknown names are skipped.
func SelectManagedAccountFields(account map[string]any, p ManagedAccountProjection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "password_policy", "target_domain":
			if _, ok := account[field]; ok {
				out[field] = common.ProjectObject(account[field], handleFields, common.OmitMissing)
			}
		case "rotation_history":
			out[field] = common.ProjectArray(account[field], rotationHistoryFields, common.OmitMissing)
		case "checkouts":
			out[field] = common.ProjectArray(account[field], checkoutFields, common.OmitMissing)
		default:
			if value, ok := account[field]; ok {
				out[field] = value
			}
		}
	}

	return out
}

// FormatManagedAccount converts a managed account to a JSON map with checkout passwords removed.
func FormatManagedAccount(v any) map[string]any {
	return RedactSensitiveTargetDomainFields(utils.ToJSONMap(v))
}

// ScannedAccountProjection is the scanned-account field set for search.
type ScannedAccountProjection struct {
	Root []string
}

// ScannedAccountProjectionFromParams merges default scanned-account fields with optional CSV extras.
func ScannedAccountProjectionFromParams(params map[string]any) ScannedAccountProjection {
	return ScannedAccountProjection{
		Root: utils.MergeUnique(DefaultScannedAccountFields, utils.CSVFromMap(params, "fields")),
	}
}

// SelectScannedAccountFields builds a filtered scanned-account map.
// target_domain keeps the handle fields. Unknown names are skipped.
func SelectScannedAccountFields(account map[string]any, p ScannedAccountProjection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "target_domain":
			if _, ok := account[field]; ok {
				out[field] = common.ProjectObject(account[field], handleFields, common.OmitMissing)
			}
		default:
			if value, ok := account[field]; ok {
				out[field] = value
			}
		}
	}

	return out
}

// FormatScannedAccountItems converts scanned accounts to response maps. When
// raw is false, fields are projected with SelectScannedAccountFields.
func FormatScannedAccountItems(items []secretsmanager.ScannedAccount, raw bool, p ScannedAccountProjection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		accountMap := utils.ToJSONMap(item)
		if !raw {
			accountMap = SelectScannedAccountFields(accountMap, p)
		}

		out = append(out, accountMap)
	}

	return out
}

// FormatManagedAccountItems converts managed accounts to response maps. When
// raw is false, fields are projected with SelectManagedAccountFields; checkout
// passwords are always redacted.
func FormatManagedAccountItems(items []secretsmanager.ManagedAccount, raw bool, p ManagedAccountProjection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		accountMap := utils.ToJSONMap(item)
		if !raw {
			accountMap = SelectManagedAccountFields(accountMap, p)
		}

		out = append(out, RedactSensitiveTargetDomainFields(accountMap))
	}

	return out
}
