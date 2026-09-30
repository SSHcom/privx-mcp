package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/hosts"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the host-delete tool definition.
//
// The tool description instructs callers to fetch the host with host-get and
// obtain explicit user confirmation before deleting. Server-side, host-delete
// verifies the host exists via GetHost, then refuses to delete it while any
// connection to the host that started within the last 24 hours (by the
// connection's `connected` timestamp) is still open (i.e. has no
// `disconnected` timestamp). Only when every connection in that window is
// closed does it call DeleteHost.
func Delete() registry.Tool {
	description := "Delete a PrivX host by id. " +
		"Fetch with host-get first and obtain explicit user confirmation using common_name and addresses. " +
		"Refused if a connection started within the last 24 hours is still open. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the host to delete.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "host-delete",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     deleteHostHandler,
	}
}

func deleteHostHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	hostID := utils.StringFromMap(params, "id")
	if hostID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	hostClient := hoststore.New(authCtx.Connector)

	// Verify the host exists before attempting anything destructive.
	if _, err := hostClient.GetHost(hostID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch host: %v", err)), nil
	}

	// Refuse to delete while a connection that started within the last 24
	// hours is still open.
	connClient := connectionmanager.New(authCtx.Connector)

	if err := hosts.AssertNoActiveConnections(connClient, hostID); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := hostClient.DeleteHost(hostID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete host: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": hostID, "deleted": true}), nil
}
