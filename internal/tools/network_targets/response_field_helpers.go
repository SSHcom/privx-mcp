package network_targets

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default field sets always returned by network-target-list and
// network-target-search when callers do not request raw output.
var (
	DefaultNetworkTargetFields = []string{
		"id",
		"name",
		"dst",
		"roles",
		"tags",
		"comment",
		"integration_type",
		"disabled",
		"exclusive_access",
	}
	DefaultRoleFields = []string{
		"id",
		"name",
	}
)

// Projection is the network-target/role field sets for list and search.
type Projection struct {
	Root  []string
	Roles []string
}

// ProjectionFromParams merges default network-target field sets with optional CSV extras.
func ProjectionFromParams(params map[string]any) Projection {
	return Projection{
		Root:  utils.MergeUnique(DefaultNetworkTargetFields, utils.CSVFromMap(params, "fields")),
		Roles: utils.MergeUnique(DefaultRoleFields, utils.CSVFromMap(params, "roleFields")),
	}
}

// SelectNetworkTargetFields builds a filtered network-target map containing
// every requested root field. Absent or JSON-null values are emitted as null
// (never omitted). When roles is a non-null array it is projected with
// roleFields; dst is kept as-is (full nested objects).
func SelectNetworkTargetFields(target map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "roles":
			out["roles"] = common.ProjectArray(target["roles"], p.Roles, common.NullMissing)
		default:
			if value, ok := target[field]; ok {
				out[field] = value
			} else {
				out[field] = nil
			}
		}
	}

	return out
}

// FormatNetworkTarget converts a network-target value to a JSON map.
func FormatNetworkTarget(v any) map[string]any {
	return utils.ToJSONMap(v)
}

// FormatNetworkTargetItems converts network targets to response maps. When
// raw is false, fields are projected with SelectNetworkTargetFields.
func FormatNetworkTargetItems(items []networkaccessmanager.NetworkTarget, raw bool, p Projection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		targetMap := utils.ToJSONMap(item)
		if !raw {
			targetMap = SelectNetworkTargetFields(targetMap, p)
		}

		out = append(out, targetMap)
	}

	return out
}
