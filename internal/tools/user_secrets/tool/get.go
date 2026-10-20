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

// Get returns the user-secret-get tool definition.
func Get() registry.Tool {
	description := "Get one PrivX secret by name. " +
		"Omit user_id for a global secret. With user_id, get that user's personal secret. " +
		"The secret key is name, not a UUID. " +
		"Returns the secret as PrivX sent it, including data. " +
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
		Set("required", []string{"name"})

	return registry.Tool{
		Name:        "user-secret-get",
		Description: description,
		Writes:      false,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     getHandler,
	}
}

func getHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	name := utils.StringFromMap(params, "name")
	if name == "" {
		return registry.ErrorResult("validation error: missing required field: name"), nil
	}

	client := vault.New(authCtx.Connector)
	userID := utils.StringFromMap(params, "user_id")

	var (
		secret *vault.Secret
		err    error
	)
	if userID == "" {
		secret, err = client.GetSecret(name)
	} else {
		secret, err = client.GetUserSecret(userID, name)
	}
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch secret: %v", err)), nil
	}

	return common.JSONResult(secret), nil
}
