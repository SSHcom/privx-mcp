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
