package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the request-get tool definition.
func Get() registry.Tool {
	description := "Fetch a single PrivX access request by id. " +
		"Returns the raw access-request record. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the access request to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "request-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getRequestHandler,
	}
}

func getRequestHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	requestID := utils.StringFromMap(params, "id")
	if requestID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := workflow.New(authCtx.Connector)

	request, err := client.GetRequest(requestID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch access request: %v", err)), nil
	}

	return common.JSONResult(request), nil
}
