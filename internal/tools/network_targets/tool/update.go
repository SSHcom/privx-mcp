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

// Update returns the network-target-update tool definition.
//
// network-target-update performs a read-modify-write full PUT against PrivX.
// The handler fetches the current target, overlays caller-supplied overrides,
// and PUTs the full target back. Server-managed fields are preserved from the
// fetched copy. dst and roles, when supplied, wholesale-replace existing arrays.
func Update() registry.Tool {
	description := "Update an existing PrivX network target by id; only supplied fields are changed. " +
		"When provided, dst and roles wholesale-replace existing arrays (omit them to preserve). " +
		`Destinations need at least selector.ip.start (end defaults to start). Roles require id. ` +
		`When proto is "All", port and nat must not be set. Does not change disabled status. ` +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the network target to update.",
		})

	network_targets.NetworkTargetEditProperties().ForEach(func(key string, value any) {
		properties.Set(key, value)
	})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "network-target-update",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     updateNetworkTargetHandler,
	}
}

func updateNetworkTargetHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	targetID := utils.StringFromMap(params, "id")
	if targetID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := networkaccessmanager.New(authCtx.Connector)

	current, err := client.GetNetworkTarget(targetID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch network target: %v", err)), nil
	}

	if err := network_targets.PatchNetworkTarget(current, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdateNetworkTarget(targetID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update network target: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": targetID, "updated": true}), nil
}
