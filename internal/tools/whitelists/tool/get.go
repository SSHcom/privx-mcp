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

// Get returns the whitelist-get tool definition.
func Get() registry.Tool {
	description := "Get a single PrivX SSH command whitelist by ID. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the whitelist to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "whitelist-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getHandler,
	}
}

func getHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	whitelistID := utils.StringFromMap(params, "id")
	if whitelistID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := hoststore.New(authCtx.Connector)

	whitelist, err := client.GetWhitelist(whitelistID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch whitelist: %v", err)), nil
	}

	return common.JSONResult(whitelist), nil
}
