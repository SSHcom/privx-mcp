package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/vault"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Delete returns the user-secret-delete tool definition.
func Delete() registry.Tool {
	description := "Delete a PrivX secret by name. " +
		"Omit user_id for a global secret. With user_id, delete that user's personal secret. " +
		"The secret key is name, not a UUID. " +
		sensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("user_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "PrivX user id. Omit for a global secret.",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Secret name (the path segment), not a UUID.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"name"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-secret-delete",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     deleteHandler,
	}
}

func deleteHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	name := utils.StringFromMap(params, "name")
	if name == "" {
		return registry.ErrorResult("validation error: missing required field: name"), nil
	}

	userID := utils.StringFromMap(params, "user_id")
	client := vault.New(authCtx.Connector)

	var err error
	if userID == "" {
		err = client.DeleteSecret(name)
	} else {
		err = client.DeleteUserSecret(userID, name)
	}

	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete secret: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"name": name, "deleted": true}), nil
}
