package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// List returns the password-policy-list tool definition.
func List() registry.Tool {
	description := "List all PrivX password rotation policies. " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", registry.NewOrderedMap())

	return registry.Tool{
		Name:        "password-policy-list",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     listHandler,
	}
}

func listHandler(ctx context.Context, _ map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	result, err := client.GetPasswordPolicies()
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch password policies: %v", err)), nil
	}

	return common.JSONResult(map[string]any{
		"items":    result.Items,
		"count":    result.Count,
		"returned": len(result.Items),
	}), nil
}
