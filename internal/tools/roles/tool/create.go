package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Create returns the create-role tool definition.
func Create() registry.Tool {
	description := "Create a new PrivX role. Name is required; permissions, comment, and tags are optional. " +
		"Complex roles with source_rules or contextual limits are better created via the PrivX GUI. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Role name.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Optional comment describing the role.",
		}).
		Set("permissions", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Optional list of PrivX permission strings to assign to the role.",
		}).
		Set("tags", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Optional tags for the role.",
		}).
		Set("access_group_id", map[string]any{
			"type":        "string",
			"description": "Optional access group ID for the role.",
		}).
		Set("context", map[string]any{
			"type":        "object",
			"description": "Optional contextual restrictions for the role.",
			"properties": map[string]any{
				"enabled": map[string]any{
					"type":        "boolean",
					"description": "Whether contextual restrictions are active.",
				},
				"block_role": map[string]any{
					"type":        "boolean",
					"description": "Block role entirely when restrictions are not met.",
				},
				"validity": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Active weekdays (e.g. [\"MON\",\"TUE\",\"WED\",\"THU\",\"FRI\"]).",
				},
				"start_time": map[string]any{
					"type":        "string",
					"description": "Daily start time (e.g. \"09:00\").",
				},
				"end_time": map[string]any{
					"type":        "string",
					"description": "Daily end time (e.g. \"17:00\").",
				},
				"timezone": map[string]any{
					"type":        "string",
					"description": "Timezone (e.g. \"UTC\", \"Europe/Helsinki\").",
				},
				"ip_masks": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Allowed source IP ranges in CIDR notation (e.g. [\"172.0.0.1/24\"]).",
				},
			},
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"name"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "role-create",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createRoleHandler,
	}
}

func createRoleHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	name := utils.StringFromMap(params, "name")
	if name == "" {
		return registry.ErrorResult("validation error: missing required field: name"), nil
	}

	role := &rolestore.Role{
		Name: name,
	}

	if comment := utils.StringFromMap(params, "comment"); comment != "" {
		role.Comment = comment
	}

	if accessGroupID := utils.StringFromMap(params, "access_group_id"); accessGroupID != "" {
		role.AccessGroupID = accessGroupID
	}

	if raw, ok := params["permissions"]; ok {
		perms, err := utils.ToStringSlice(raw)
		if err != nil {
			return registry.ErrorResult(fmt.Sprintf("validation error: permissions: %v", err)), nil
		}

		role.Permissions = perms
	}

	if raw, ok := params["tags"]; ok {
		tags, err := utils.ToStringSlice(raw)
		if err != nil {
			return registry.ErrorResult(fmt.Sprintf("validation error: tags: %v", err)), nil
		}

		role.Tags = tags
	}

	if raw, ok := params["context"]; ok {
		if ctxMap, ok := raw.(map[string]any); ok {
			role.Context = parseRoleContext(ctxMap)
		}
	}

	client := rolestore.New(authCtx.Connector)

	identifier, err := client.CreateRole(role)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create role: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
