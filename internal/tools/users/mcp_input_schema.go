package users

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// LocalUserEditProperties returns the shared set of editable local-user
// properties used by user-update-local. Server-managed and sensitive fields
// (id, created, updated, updated_by, author, source, stale_access_token,
// mfa, password, password_change_required) are intentionally omitted.
func LocalUserEditProperties() *registry.OrderedMap {
	return registry.NewOrderedMap().
		Set("username", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Local username (principal). Applied only when the key is present.",
		}).
		Set("full_name", map[string]any{
			"type":        "string",
			"description": "User full name. Applied only when the key is present.",
		}).
		Set("email", map[string]any{
			"type":        "string",
			"description": "User email address. Applied only when the key is present.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Comment. Applied only when the key is present.",
		}).
		Set("tags", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Tags. Wholesale-replaces the existing list when present.",
		}).
		Set("windows_account", map[string]any{
			"type":        "string",
			"description": "Windows account. Applied only when the key is present.",
		}).
		Set("unix_account", map[string]any{
			"type":        "string",
			"description": "Unix account. Applied only when the key is present.",
		}).
		Set("display_name", map[string]any{
			"type":        "string",
			"description": "Display name. Applied only when the key is present.",
		}).
		Set("first_name", map[string]any{
			"type":        "string",
			"description": "First name. Applied only when the key is present.",
		}).
		Set("last_name", map[string]any{
			"type":        "string",
			"description": "Last name. Applied only when the key is present.",
		}).
		Set("job_title", map[string]any{
			"type":        "string",
			"description": "Job title. Applied only when the key is present.",
		}).
		Set("company", map[string]any{
			"type":        "string",
			"description": "Company. Applied only when the key is present.",
		}).
		Set("department", map[string]any{
			"type":        "string",
			"description": "Department. Applied only when the key is present.",
		}).
		Set("telephone", map[string]any{
			"type":        "string",
			"description": "Telephone. Applied only when the key is present.",
		}).
		Set("locale", map[string]any{
			"type":        "string",
			"description": "Locale. Applied only when the key is present.",
		})
}
