package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/hosts"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the host-get tool definition.
func Get() registry.Tool {
	description := "Fetch a single PrivX host by id. " +
		"For connection link creation guidance, see mcp-info -> context: connection. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the host to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "host-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getHostHandler,
	}
}

func getHostHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	hostID := utils.StringFromMap(params, "id")
	if hostID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := hoststore.New(authCtx.Connector)

	host, err := client.GetHost(hostID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch host: %v", err)), nil
	}

	return common.JSONResult(hosts.FormatHost(host)), nil
}
