package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Update returns the whitelist-update tool definition.
func Update() registry.Tool {
	description := "Update a PrivX SSH command whitelist by ID. " +
		"This is a full replacement update. " +
		"Always fetch the current state with whitelist-get first to avoid overwriting fields. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the whitelist to update.",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"description": "Whitelist name.",
		}).
		Set("type", map[string]any{
			"type":        "string",
			"enum":        []string{"glob", "regex"},
			"description": `Whitelist type: "glob" or "regex".`,
		}).
		Set("whitelist_patterns", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "List of allowed command patterns.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Optional comment describing the whitelist.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "whitelist-update",
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

	whitelistID := utils.StringFromMap(params, "id")
	if whitelistID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := hoststore.New(authCtx.Connector)

	// Fetch current state for full replacement.
	current, err := client.GetWhitelist(whitelistID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch whitelist: %v", err)), nil
	}

	// Overlay supplied fields onto the current whitelist.
	if name, ok, err := utils.OverlayString(params, "name"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok && name != "" {
		current.Name = name
	}

	if wlType, ok, err := utils.OverlayString(params, "type"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok && wlType != "" {
		if wlType != "glob" && wlType != "regex" {
			return registry.ErrorResult(`validation error: type must be "glob" or "regex"`), nil
		}

		current.Type = wlType
	}

	if raw, ok := params["whitelist_patterns"]; ok {
		patterns, err := utils.ToStringSlice(raw)
		if err != nil {
			return registry.ErrorResult(fmt.Sprintf("validation error: whitelist_patterns: %v", err)), nil
		}

		current.WhiteListPatterns = patterns
	}

	if comment, ok, err := utils.OverlayString(params, "comment"); err != nil {
		return registry.ErrorResult("validation error: " + err.Error()), nil
	} else if ok {
		current.Comment = comment
	}

	if err := client.UpdateWhitelist(whitelistID, *current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update whitelist: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": whitelistID, "updated": true}), nil
}
