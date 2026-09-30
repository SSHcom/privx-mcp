package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/users"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Get returns the user-get tool definition.
func Get() registry.Tool {
	description := "Fetch a single PrivX user by id. " + common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the user to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "user-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getUserHandler,
	}
}

func getUserHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	userID := utils.StringFromMap(params, "id")
	if userID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := rolestore.New(authCtx.Connector)

	user, err := client.GetUser(userID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch user: %v", err)), nil
	}

	return common.JSONResult(users.FormatUser(user)), nil
}
