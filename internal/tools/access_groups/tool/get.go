package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the access-group-get tool definition.
func Get() registry.Tool {
	description := "Get a single PrivX access group by ID. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the access group to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "access-group-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getHandler,
	}
}

func getHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	accessGroupID := utils.StringFromMap(params, "id")
	if accessGroupID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := authorizer.New(authCtx.Connector)

	accessGroup, err := client.GetAccessGroup(accessGroupID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch access group: %v", err)), nil
	}

	return common.JSONResult(redactAccessGroup(accessGroup)), nil
}

func redactAccessGroup(v any) map[string]any {
	m := utils.ToJSONMap(v)
	common.DeletePaths(m,
		"host_certificate_trust_anchors",
		"db_host_certificate_trust_anchors",
		"winrm_host_certificate_trust_anchors",
	)

	return m
}
