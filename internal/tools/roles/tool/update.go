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

// Update returns the update-role tool definition.
func Update() registry.Tool {
	description := "Update a PrivX role by id. This is a full replacement update. " +
		"Always fetch the current state with get-role first to avoid overwriting fields you did not intend to change. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the role to update.",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"description": "Role name.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Comment describing the role.",
		}).
		Set("permissions", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "PrivX permission strings assigned to the role.",
		}).
		Set("tags", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Tags for the role.",
		}).
		Set("access_group_id", map[string]any{
			"type":        "string",
			"description": "Access group ID for the role.",
		}).
		Set("permit_agent", map[string]any{
			"type":        "boolean",
			"description": "Whether SSH agent forwarding is permitted.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "role-update",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     updateRoleHandler,
	}
}

func updateRoleHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	roleID := utils.StringFromMap(params, "id")
	if roleID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := rolestore.New(authCtx.Connector)

	// Fetch current state for full replacement.
	current, err := client.GetRole(roleID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch role: %v", err)), nil
	}

	// Overlay supplied fields onto the current role.
	if name, ok, err := utils.OverlayString(params, "name"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok && name != "" {
		current.Name = name
	}

	if comment, ok, err := utils.OverlayString(params, "comment"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.Comment = comment
	}

	if accessGroupID, ok, err := utils.OverlayString(params, "access_group_id"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.AccessGroupID = accessGroupID
	}

	if permitAgent, ok, err := utils.OverlayBool(params, "permit_agent"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.PermitAgent = permitAgent
	}

	if raw, ok := params["permissions"]; ok {
		perms, err := utils.ToStringSlice(raw)
		if err != nil {
			return registry.ErrorResult(fmt.Sprintf("validation error: permissions: %v", err)), nil
		}

		current.Permissions = perms
	}

	if raw, ok := params["tags"]; ok {
		tags, err := utils.ToStringSlice(raw)
		if err != nil {
			return registry.ErrorResult(fmt.Sprintf("validation error: tags: %v", err)), nil
		}

		current.Tags = tags
	}

	if raw, ok := params["context"]; ok {
		if ctxMap, ok := raw.(map[string]any); ok {
			current.Context = parseRoleContext(ctxMap)
		}
	}

	if err := client.UpdateRole(roleID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update role: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": roleID, "updated": true}), nil
}
