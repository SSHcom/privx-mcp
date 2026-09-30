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

// Revoke returns the request-revoke-role tool definition.
func Revoke() registry.Tool {
	description := "Revoke the target role granted by a PrivX access request. " +
		"Calls the workflow-engine role revoke endpoint for the given request id. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the access request whose target role should be revoked.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "request-revoke-role",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     revokeRequestRoleHandler,
	}
}

func revokeRequestRoleHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	requestID := utils.StringFromMap(params, "id")
	if requestID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := workflow.New(authCtx.Connector)
	if err := client.RevokeTargetRole(requestID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to revoke target role: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": requestID, "revoked": true}), nil
}
