package hosts

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default field sets always returned by host-list and host-search when
// callers do not request raw output.
var (
	DefaultHostFields = []string{
		"id",
		"common_name",
		"addresses",
		"disabled",
		"services",
		"principals",
	}
	DefaultServiceFields = []string{
		"service",
		"address",
		"status",
	}
	DefaultPrincipalFields = []string{
		"principal",
		"roles",
	}

	// Sensitive paths always stripped from host tool responses (get/list/search),
	// including raw output and explicit field projection requests.
	sensitiveHostPaths = []string{
		"host_certificate_raw",
		"host_certificate",
		"ssh_host_public_keys",
		"password_rotation",
		"password_rotation_enabled",
		"services[].use_for_password_rotation",
		"services[].certificate_template",
		"services[].db.tls_certificate_trust_anchors",
		"services[].db.tls_certificate_validation",
		"principals[].passphrase",
		"principals[].use_for_password_rotation",
		"principals[].rotate",
	}
)

// Projection is the host/service/principal field sets for list and search.
type Projection struct {
	Root       []string
	Services   []string
	Principals []string
}

// ProjectionFromParams merges default host field sets with optional CSV extras.
func ProjectionFromParams(params map[string]any) Projection {
	return Projection{
		Root:       utils.MergeUnique(DefaultHostFields, utils.CSVFromMap(params, "fields")),
		Services:   utils.MergeUnique(DefaultServiceFields, utils.CSVFromMap(params, "serviceFields")),
		Principals: utils.MergeUnique(DefaultPrincipalFields, utils.CSVFromMap(params, "principalFields")),
	}
}

// SelectHostFields builds a filtered host map containing only the requested
// root fields. Services and principals are filtered recursively with their
// own field sets. Field names that cannot be found on the source item are
// skipped.
func SelectHostFields(host map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "services":
			out["services"] = common.ProjectArray(host["services"], p.Services, common.OmitMissing)
		case "principals":
			out["principals"] = common.ProjectArray(host["principals"], p.Principals, common.OmitMissing)
		default:
			if value, ok := host[field]; ok {
				out[field] = value
			}
		}
	}

	return out
}

// RedactSensitiveHostFields removes password-, certificate-, and
// rotation-related fields from a host JSON map in place and returns it.
func RedactSensitiveHostFields(host map[string]any) map[string]any {
	if host == nil {
		return nil
	}

	common.DeletePaths(host, sensitiveHostPaths...)

	return host
}

// FormatHost converts a host value to a JSON map with sensitive fields removed.
func FormatHost(v any) map[string]any {
	return RedactSensitiveHostFields(utils.ToJSONMap(v))
}

// FormatHostItems converts host-store hosts to response maps. When raw is
// false, fields are projected with SelectHostFields; sensitive fields are
// always redacted.
func FormatHostItems(items []hoststore.Host, raw bool, p Projection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		hostMap := utils.ToJSONMap(item)
		if !raw {
			hostMap = SelectHostFields(hostMap, p)
		}

		out = append(out, RedactSensitiveHostFields(hostMap))
	}

	return out
}
