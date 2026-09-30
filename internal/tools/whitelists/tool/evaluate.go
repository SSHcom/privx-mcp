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

// Evaluate returns the whitelist-evaluate tool definition.
func Evaluate() registry.Tool {
	description := "Evaluate commands against a whitelist's patterns. " +
		"This is a dry-run test — it does not execute commands or modify anything. " +
		"Returns whether each command would be allowed or blocked. " +
		`Use rshell_variant 'bash' or 'posix'. ` +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the whitelist to evaluate against.",
		}).
		Set("commands", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"description": "Commands to test against the whitelist patterns.",
		}).
		Set("rshell_variant", map[string]any{
			"type":        "string",
			"enum":        []string{"bash", "posix"},
			"description": `Shell variant: "bash" or "posix". Defaults to "bash".`,
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "commands"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "whitelist-evaluate",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     evaluateHandler,
	}
}

func evaluateHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	whitelistID := utils.StringFromMap(params, "id")
	if whitelistID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	rawCommands, ok := params["commands"]
	if !ok || rawCommands == nil {
		return registry.ErrorResult("validation error: missing required field: commands"), nil
	}

	commands, err := utils.ToStringSlice(rawCommands)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: commands: %v", err)), nil
	}

	if len(commands) == 0 {
		return registry.ErrorResult("validation error: commands must not be empty"), nil
	}

	rshellVariant := utils.StringFromMap(params, "rshell_variant")
	if rshellVariant == "" {
		rshellVariant = "bash"
	}

	client := hoststore.New(authCtx.Connector)

	// Fetch the whitelist to populate the evaluate request.
	whitelist, err := client.GetWhitelist(whitelistID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch whitelist: %v", err)), nil
	}

	evaluate := &hoststore.WhitelistEvaluate{
		WhiteList:     *whitelist,
		RShellVariant: rshellVariant,
		Commands:      commands,
	}

	result, err := client.EvaluateWhitelist(evaluate)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to evaluate whitelist: %v", err)), nil
	}

	return common.JSONResult(result), nil
}
