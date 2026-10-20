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

// Update returns the user-secret-update tool definition.
func Update() registry.Tool {
	description := "Update a PrivX secret by name. " +
		"Omit user_id for a global secret. With user_id, update that user's personal secret and set owner_id from it. " +
		"This is a full replacement of the secret request after overlay: the current secret is fetched, then data, read_roles, and write_roles replace the stored values when those arguments are set. " +
		"The secret key is name, not a UUID. " +
		"data is a free-form object and is stored as given. " +
		"read_roles and write_roles take objects with id and an optional name. " +
		sensitiveDataGuidance + " " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", secretWriteProperties()).
		Set("required", []string{"name"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-secret-update",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     updateHandler,
	}
}

func updateHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
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

	var (
		current *vault.Secret
		err     error
	)
	if userID == "" {
		current, err = client.GetSecret(name)
	} else {
		current, err = client.GetUserSecret(userID, name)
	}
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch secret: %v", err)), nil
	}

	req := current.SecretRequest
	req.Name = name
	req.OwnerID = userID
	if errResult := overlaySecret(&req, params); errResult != nil {
		return errResult, nil
	}

	if userID == "" {
		err = client.UpdateSecret(name, &req)
	} else {
		err = client.UpdateUserSecret(userID, name, &req)
	}
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update secret: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"name": name, "updated": true}), nil
}

func overlaySecret(req *vault.SecretRequest, params map[string]any) *registry.ToolResult {
	if raw, ok := params["data"]; ok {
		data, ok := raw.(map[string]any)
		if !ok {
			return registry.ErrorResult("validation error: data must be an object")
		}

		req.Data = &data
	}

	readRoles, errResult := optionalRoles(params, "read_roles")
	if errResult != nil {
		return errResult
	}

	if readRoles != nil {
		req.ReadRoles = readRoles
	}

	writeRoles, errResult := optionalRoles(params, "write_roles")
	if errResult != nil {
		return errResult
	}

	if writeRoles != nil {
		req.WriteRoles = writeRoles
	}

	if req.ReadRoles == nil {
		req.ReadRoles = []rolestore.RoleHandle{}
	}

	if req.WriteRoles == nil {
		req.WriteRoles = []rolestore.RoleHandle{}
	}

	return nil
}
