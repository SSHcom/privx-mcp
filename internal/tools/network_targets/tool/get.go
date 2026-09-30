package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/network_targets"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the network-target-get tool definition.
func Get() registry.Tool {
	description := "Fetch a single PrivX network target by id. " + common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the network target to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "network-target-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getNetworkTargetHandler,
	}
}

func getNetworkTargetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	targetID := utils.StringFromMap(params, "id")
	if targetID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := networkaccessmanager.New(authCtx.Connector)

	target, err := client.GetNetworkTarget(targetID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch network target: %v", err)), nil
	}

	return common.JSONResult(network_targets.FormatNetworkTarget(target)), nil
}
