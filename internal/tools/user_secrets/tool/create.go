package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/SSHcom/privx-sdk-go/v2/api/vault"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Create returns the user-secret-create tool definition.
func Create() registry.Tool {
	description := "Create a PrivX secret. " +
		"Omit user_id for a global secret. With user_id, create that user's personal secret and set owner_id from it. " +
		"The secret key is name, not a UUID. " +
		"data is a free-form object and is stored as given. " +
		"read_roles and write_roles take objects with id and an optional name. " +
		"Returns the created secret name. " +
		sensitiveDataGuidance + " " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", secretWriteProperties()).
		Set("required", []string{"name"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-secret-create",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     createHandler,
	}
}

func secretWriteProperties() *registry.OrderedMap {
	roleItem := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id":   map[string]any{"type": "string", "minLength": 1, "description": "PrivX role id."},
			"name": map[string]any{"type": "string", "description": "Role name. Optional."},
		},
		"required":             []string{"id"},
		"additionalProperties": false,
	}

	return registry.NewOrderedMap().
		Set("user_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "PrivX user id. Omit for a global secret. When set, stored as owner_id.",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Secret name (the path segment), not a UUID.",
		}).
		Set("data", map[string]any{
			"type":                 "object",
			"description":          "Secret payload. Nested keys are kept as given.",
			"additionalProperties": true,
		}).
		Set("read_roles", map[string]any{
			"type":        "array",
			"description": "Roles that can read the secret.",
			"items":       roleItem,
		}).
		Set("write_roles", map[string]any{
			"type":        "array",
			"description": "Roles that can modify the secret.",
			"items":       roleItem,
		})
}

func createHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	userID := utils.StringFromMap(params, "user_id")

	secret, errResult := secretRequest(userID, params)
	if errResult != nil {
		return errResult, nil
	}

	client := vault.New(authCtx.Connector)

	var (
		created vault.SecretCreate
		err     error
	)
	if userID == "" {
		created, err = client.CreateSecret(secret)
	} else {
		created, err = client.CreateUserSecret(userID, secret)
	}
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create secret: %v", err)), nil
	}

	return common.JSONResult(created), nil
}

func secretRequest(userID string, params map[string]any) (*vault.SecretRequest, *registry.ToolResult) {
	name := utils.StringFromMap(params, "name")
	if name == "" {
		return nil, registry.ErrorResult("validation error: missing required field: name")
	}

	req := &vault.SecretRequest{
		Name:       name,
		OwnerID:    userID,
		ReadRoles:  []rolestore.RoleHandle{},
		WriteRoles: []rolestore.RoleHandle{},
	}

	if raw, ok := params["data"]; ok {
		data, ok := raw.(map[string]any)
		if !ok {
			return nil, registry.ErrorResult("validation error: data must be an object")
		}

		req.Data = &data
	}

	readRoles, errResult := optionalRoles(params, "read_roles")
	if errResult != nil {
		return nil, errResult
	}

	if readRoles != nil {
		req.ReadRoles = readRoles
	}

	writeRoles, errResult := optionalRoles(params, "write_roles")
	if errResult != nil {
		return nil, errResult
	}

	if writeRoles != nil {
		req.WriteRoles = writeRoles
	}

	return req, nil
}

func optionalRoles(params map[string]any, key string) ([]rolestore.RoleHandle, *registry.ToolResult) {
	raw, ok := params[key]
	if !ok {
		return nil, nil
	}

	roles, err := roleHandles(raw)
	if err != nil {
		return nil, registry.ErrorResult(fmt.Sprintf("validation error: %s: %v", key, err))
	}

	return roles, nil
}

func roleHandles(raw any) ([]rolestore.RoleHandle, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}

	out := make([]rolestore.RoleHandle, 0, len(items))
	for i, item := range items {
		role, err := roleHandle(item)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}

		out = append(out, role)
	}

	return out, nil
}

func roleHandle(raw any) (rolestore.RoleHandle, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return rolestore.RoleHandle{}, fmt.Errorf("must be an object")
	}

	id := utils.StringFromMap(m, "id")
	if id == "" {
		return rolestore.RoleHandle{}, fmt.Errorf("missing required field: id")
	}

	return rolestore.RoleHandle{
		ID:   id,
		Name: utils.StringFromMap(m, "name"),
	}, nil
}
