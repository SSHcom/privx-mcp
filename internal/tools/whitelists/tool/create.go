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

// Create returns the whitelist-create tool definition.
func Create() registry.Tool {
	description := "Create a new SSH command whitelist. " +
		"Name, type (glob or regex), and whitelist_patterns are required. " +
		"Glob patterns use shell wildcards (*, ?). " +
		"Regex patterns must start with ^ and use Go RE2 syntax. " +
		"Security warning: overly broad patterns (e.g. ** in glob or .* in regex) defeat the purpose of command restrictions. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
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
		Set("required", []string{"name", "type", "whitelist_patterns"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "whitelist-create",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createHandler,
	}
}

func createHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	name := utils.StringFromMap(params, "name")
	if name == "" {
		return registry.ErrorResult("validation error: missing required field: name"), nil
	}

	wlType := utils.StringFromMap(params, "type")
	if wlType == "" {
		return registry.ErrorResult("validation error: missing required field: type"), nil
	}

	if wlType != "glob" && wlType != "regex" {
		return registry.ErrorResult(`validation error: type must be "glob" or "regex"`), nil
	}

	rawPatterns, ok := params["whitelist_patterns"]
	if !ok || rawPatterns == nil {
		return registry.ErrorResult("validation error: missing required field: whitelist_patterns"), nil
	}

	patterns, err := utils.ToStringSlice(rawPatterns)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: whitelist_patterns: %v", err)), nil
	}

	if len(patterns) == 0 {
		return registry.ErrorResult("validation error: whitelist_patterns must not be empty"), nil
	}

	whitelist := &hoststore.Whitelist{
		Name:              name,
		Type:              wlType,
		WhiteListPatterns: patterns,
		Comment:           utils.StringFromMap(params, "comment"),
	}

	client := hoststore.New(authCtx.Connector)

	identifier, err := client.CreateWhitelist(whitelist)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create whitelist: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
