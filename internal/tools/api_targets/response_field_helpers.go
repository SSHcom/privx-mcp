package api_targets

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default field sets always returned by api-target-list when callers do not
// request raw output.
var (
	DefaultAPITargetFields = []string{
		"id",
		"name",
		"access_group_id",
		"roles",
		"authorized_endpoints",
	}
	DefaultRoleFields = []string{
		"id",
		"name",
	}
	DefaultEndpointFields = []string{
		"host",
		"nat_target_host",
		"allow_unauthenticated",
		"protocols",
		"methods",
		"paths",
	}

	// Sensitive paths always stripped from api-target tool responses
	// (get/list), including raw output and explicit field projection requests.
	sensitiveAPITargetPaths = []string{
		"tls_trust_anchors",
		"target_credential.basic_auth_password",
		"target_credential.bearer_token",
		"target_credential.certificate",
		"target_credential.private_key",
	}
)

// Projection is the api-target/role/endpoint field sets for list.
type Projection struct {
	Root      []string
	Roles     []string
	Endpoints []string
}

// ProjectionFromParams merges default api-target field sets with optional CSV extras.
func ProjectionFromParams(params map[string]any) Projection {
	return Projection{
		Root:      utils.MergeUnique(DefaultAPITargetFields, utils.CSVFromMap(params, "fields")),
		Roles:     utils.MergeUnique(DefaultRoleFields, utils.CSVFromMap(params, "roleFields")),
		Endpoints: utils.MergeUnique(DefaultEndpointFields, utils.CSVFromMap(params, "endpointFields")),
	}
}

// SelectAPITargetFields builds a filtered api-target map containing only the
// requested root fields. Roles and endpoint arrays are filtered recursively
// with their own field sets. Field names that cannot be found on the source
// item are skipped. Absent nested endpoint keys (e.g. empty nat_target_host)
// are omitted.
func SelectAPITargetFields(target map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "roles":
			out["roles"] = common.ProjectArray(target["roles"], p.Roles, common.OmitMissing)
		case "authorized_endpoints", "unauthorized_endpoints":
			out[field] = common.ProjectArray(target[field], p.Endpoints, common.OmitMissing)
		default:
			if value, ok := target[field]; ok {
				out[field] = value
			}
		}
	}

	return out
}

// RedactSensitiveAPITargetFields removes certificate trust anchors and
// credential secrets from an api-target JSON map in place and returns it.
func RedactSensitiveAPITargetFields(target map[string]any) map[string]any {
	if target == nil {
		return nil
	}

	common.DeletePaths(target, sensitiveAPITargetPaths...)

	return target
}

// FormatAPITarget converts an api-target value to a JSON map with sensitive
// fields removed.
func FormatAPITarget(v any) map[string]any {
	return RedactSensitiveAPITargetFields(utils.ToJSONMap(v))
}

// FormatAPITargetItems converts api targets to response maps. When raw is
// false, fields are projected with SelectAPITargetFields; sensitive fields are
// always redacted.
func FormatAPITargetItems(items []apiproxy.ApiTarget, raw bool, p Projection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		targetMap := utils.ToJSONMap(item)
		if !raw {
			targetMap = SelectAPITargetFields(targetMap, p)
		}

		out = append(out, RedactSensitiveAPITargetFields(targetMap))
	}

	return out
}
