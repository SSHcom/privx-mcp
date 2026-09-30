package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/api_targets"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the api-target-get tool definition.
func Get() registry.Tool {
	description := "Fetch a single PrivX API target by id. Sensitive credential fields are omitted. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the API target to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "api-target-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getAPITargetHandler,
	}
}

func getAPITargetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	targetID := utils.StringFromMap(params, "id")
	if targetID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := apiproxy.New(authCtx.Connector)

	target, err := client.GetApiTarget(targetID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch API target: %v", err)), nil
	}

	return common.JSONResult(api_targets.FormatAPITarget(target)), nil
}
