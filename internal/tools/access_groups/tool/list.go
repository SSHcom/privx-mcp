package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// List returns the access-group-list tool definition.
func List() registry.Tool {
	description := "List all PrivX access groups. " +
		"Access groups partition the PrivX environment into security domains with separate CAs. " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", registry.NewOrderedMap())

	return registry.Tool{
		Name:        "access-group-list",
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

	client := authorizer.New(authCtx.Connector)

	result, err := client.GetAccessGroups()
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch access groups: %v", err)), nil
	}

	items := make([]map[string]any, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, redactAccessGroup(item))
	}

	return common.JSONResult(map[string]any{
		"items":    items,
		"count":    result.Count,
		"returned": len(result.Items),
	}), nil
}
