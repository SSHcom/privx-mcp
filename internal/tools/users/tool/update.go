package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/users"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Update returns the user-update-local tool definition.
//
// user-update-local performs a read-modify-write full PUT against the PrivX Local
// User Store. The handler fetches the current local user, overlays
// caller-supplied overrides for every editable profile field, and PUTs the
// full user back. Password fields are never accepted as input; they are
// preserved from the fetched copy.
func Update() registry.Tool {
	description := "Update an existing local PrivX user by id; only supplied fields are changed. " +
		"Local users only; directory users cannot be modified here. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the local user to update.",
		})

	users.LocalUserEditProperties().ForEach(func(key string, value any) {
		properties.Set(key, value)
	})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-update-local",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     updateUserHandler,
	}
}

func updateUserHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	userID := utils.StringFromMap(params, "id")
	if userID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := userstore.New(authCtx.Connector)

	current, err := client.GetUser(userID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch local user: %v", err)), nil
	}

	if err := users.PatchLocalUser(current, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdateUser(userID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update local user: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": userID, "updated": true}), nil
}
