package users

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default field sets always returned by user-list and user-search when
// callers do not request raw output.
var (
	DefaultUserFields = []string{
		"id",
		"principal",
		"source",
		"source_type",
		"email",
		"full_name",
		"roles",
	}
	DefaultRoleFields = []string{
		"id",
		"name",
	}

	// DefaultUserRoleFields are root fields always returned by user-get-roles
	// when callers do not request raw output.
	DefaultUserRoleFields = []string{
		"id",
		"name",
	}
	// DefaultUserRoleContextFields are context fields always returned nested
	// under context by user-get-roles when callers do not request raw output.
	DefaultUserRoleContextFields = []string{
		"enabled",
	}

	// Sensitive paths always stripped from user tool responses (get/list/search),
	// including raw output and explicit field projection requests.
	// mfa.seed removes the seed object and leaves the rest of mfa.
	// windows_sid attribute entries are dropped separately.
	sensitiveUserPaths = []string{
		"password",
		"settings",
		"authorized_keys",
		"webauthn_credentials",
		"mfa.seed",
		"roles[].principal_public_key_strings",
		"roles[].context.ip_masks",
	}
	// windowsSIDAttribute is the attributes[].key value removed from user payloads.
	windowsSIDAttribute = "windows_sid"

	// Sensitive paths always stripped from role objects (role-get, role-list,
	// user-get-roles), including raw output and explicit field requests.
	sensitiveRolePaths = []string{
		"principal_public_key_strings",
		"context.ip_masks",
	}
)

// Projection is the user/role field sets for list and search.
type Projection struct {
	Root  []string
	Roles []string
}

// ProjectionFromParams merges default user field sets with optional CSV extras.
func ProjectionFromParams(params map[string]any) Projection {
	return Projection{
		Root:  utils.MergeUnique(DefaultUserFields, utils.CSVFromMap(params, "fields")),
		Roles: utils.MergeUnique(DefaultRoleFields, utils.CSVFromMap(params, "roleFields")),
	}
}

// SelectUserFields builds a filtered user map containing every requested root
// field. Absent or JSON-null values are emitted as null (never omitted). When
// roles is a non-null array it is projected with roleFields; when roles is
// null/absent the key is kept as null (not coerced to []).
func SelectUserFields(user map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "roles":
			out["roles"] = common.ProjectArray(user["roles"], p.Roles, common.NullMissing)
		default:
			if value, ok := user[field]; ok {
				out[field] = value
			} else {
				out[field] = nil
			}
		}
	}

	return out
}

// RedactSensitiveUserFields removes credential fields from a user JSON map in
// place and returns it. Nested role public keys and context ip_masks are
// stripped, mfa.seed is removed, and windows_sid attribute entries are dropped.
func RedactSensitiveUserFields(user map[string]any) map[string]any {
	if user == nil {
		return nil
	}

	common.DeletePaths(user, sensitiveUserPaths...)
	common.DropNamedAttributes(user, "attributes", windowsSIDAttribute)

	return user
}

// FormatUser converts a user value to a JSON map with sensitive fields removed.
func FormatUser(v any) map[string]any {
	return RedactSensitiveUserFields(utils.ToJSONMap(v))
}

// FormatUserItems converts role-store users to response maps. When raw is
// false, fields are projected with SelectUserFields; sensitive fields are
// always redacted.
func FormatUserItems(items []rolestore.User, raw bool, p Projection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		userMap := utils.ToJSONMap(item)
		if !raw {
			userMap = SelectUserFields(userMap, p)
		}

		out = append(out, RedactSensitiveUserFields(userMap))
	}

	return out
}

// SelectUserRoleFields builds a filtered role map for user-get-roles.
// Root fields are always id and name; context is projected with contextFields;
// source_rules is included only when includeSourceRules is true. Absent or
// JSON-null values are emitted as null (never omitted).
func SelectUserRoleFields(role map[string]any, includeSourceRules bool, contextFields []string) map[string]any {
	out := make(map[string]any, 4)

	for _, field := range DefaultUserRoleFields {
		if value, ok := role[field]; ok {
			out[field] = value
		} else {
			out[field] = nil
		}
	}

	out["context"] = common.ProjectObject(role["context"], contextFields, common.NullMissing)
	if includeSourceRules {
		if value, ok := role["source_rules"]; ok {
			out["source_rules"] = value
		} else {
			out["source_rules"] = nil
		}
	}

	return out
}

// RedactSensitiveRoleFields removes credential-related fields from a role JSON
// map in place and returns it.
func RedactSensitiveRoleFields(role map[string]any) map[string]any {
	if role == nil {
		return nil
	}

	common.DeletePaths(role, sensitiveRolePaths...)

	return role
}

// FormatUserRoleItems converts role-store roles to response maps for
// user-get-roles. When raw is false, fields are projected with
// SelectUserRoleFields; sensitive fields are always redacted.
func FormatUserRoleItems(items []rolestore.Role, raw, includeSourceRules bool, contextFields []string) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		roleMap := utils.ToJSONMap(item)
		if !raw {
			roleMap = SelectUserRoleFields(roleMap, includeSourceRules, contextFields)
		}

		out = append(out, RedactSensitiveRoleFields(roleMap))
	}

	return out
}
