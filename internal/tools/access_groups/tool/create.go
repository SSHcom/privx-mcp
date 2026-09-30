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

// Create returns the access-group-create tool definition.
func Create() registry.Tool {
	description := "Create a new PrivX access group. " +
		"Name is required. Access groups partition the environment into security domains " +
		"with separate certificate authorities. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Access group name.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Optional description of the access group.",
		}).
		Set("ca_id", map[string]any{
			"type":        "string",
			"description": "Comma-separated UUIDs of access group CAs.",
		}).
		Set("primary_ca_id", map[string]any{
			"type":        "string",
			"description": "UUID of the primary certificate authority.",
		}).
		Set("key_type", map[string]any{
			"type":        "string",
			"description": "CA key type (e.g. \"RSA:2048\", \"ECDSA:P256\").",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"name"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "access-group-create",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createHandler,
	}
}

func createHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	name := utils.StringFromMap(params, "name")
	if name == "" {
		return registry.ErrorResult("validation error: missing required field: name"), nil
	}

	accessGroup := &authorizer.AccessGroup{
		Name:        name,
		Comment:     utils.StringFromMap(params, "comment"),
		CAID:        utils.StringFromMap(params, "ca_id"),
		PrimaryCAID: utils.StringFromMap(params, "primary_ca_id"),
		CAKeyType:   utils.StringFromMap(params, "key_type"),
	}

	client := authorizer.New(authCtx.Connector)

	identifier, err := client.CreateAccessGroup(accessGroup)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create access group: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
