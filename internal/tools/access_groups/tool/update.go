package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Update returns the access-group-update tool definition.
func Update() registry.Tool {
	description := "Update a PrivX access group by ID. " +
		"This is a full replacement update. " +
		"Always fetch the current state with access-group-get first to avoid overwriting fields. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the access group to update.",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"description": "Access group name.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Description of the access group.",
		}).
		Set("ca_id", map[string]any{
			"type":        "string",
			"description": "Comma-separated UUIDs of access group CAs.",
		}).
		Set("primary_ca_id", map[string]any{
			"type":        "string",
			"description": "UUID of the primary certificate authority.",
		}).
		Set("key_type", map[string]any{
			"type":        "string",
			"description": "CA key type (e.g. \"RSA:2048\", \"ECDSA:P256\").",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "access-group-update",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     updateHandler,
	}
}

func updateHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	accessGroupID := utils.StringFromMap(params, "id")
	if accessGroupID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := authorizer.New(authCtx.Connector)

	// Fetch current state for full replacement.
	current, err := client.GetAccessGroup(accessGroupID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch access group: %v", err)), nil
	}

	// Overlay supplied fields onto the current access group.
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

	if caID, ok, err := utils.OverlayString(params, "ca_id"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.CAID = caID
	}

	if primaryCAID, ok, err := utils.OverlayString(params, "primary_ca_id"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.PrimaryCAID = primaryCAID
	}

	if keyType, ok, err := utils.OverlayString(params, "key_type"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.CAKeyType = keyType
	}

	if err := client.UpdateAccessGroup(accessGroupID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update access group: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": accessGroupID, "updated": true}), nil
}
