package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/network_targets"
)

// Create returns the network-target-create tool definition.
func Create() registry.Tool {
	description := "Create a PrivX network target. " +
		"Requires name; destinations need at least selector.ip.start (end defaults to start). " +
		`Roles require id. When proto is "All", port and nat must not be set. ` +
		"Returns the created network target id; use network-target-update for further edits. " +
		common.PresentationGuidance

	properties := network_targets.NetworkTargetCreateProperties()

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"name"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "network-target-create",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createNetworkTargetHandler,
	}
}

func createNetworkTargetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	target, err := network_targets.BuildNetworkTargetFromCreateParams(params)
	if err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	identifier, err := networkaccessmanager.New(authCtx.Connector).CreateNetworkTarget(target)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create network target: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
