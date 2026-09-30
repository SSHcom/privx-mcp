package tool

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// randomPasswordBytes is the entropy used for the generated initial password
// (base64url-encoded to ~32 characters).
const randomPasswordBytes = 24

// Create returns the user-create-local tool definition.
//
// Required fields: username, full_name, email. A random initial password is
// generated server-side (never accepted as an input param and never returned),
// with password_change_required=true.
func Create() registry.Tool {
	description := "Create a local PrivX user with username, full_name, and email. " +
		"Initial password is generated server-side and not returned (user must change it). Local users only; returns the created user id. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("username", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Local username (principal).",
		}).
		Set("full_name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "User full name.",
		}).
		Set("email", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "User email address.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"username", "full_name", "email"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "user-create-local",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createLocalUserHandler,
	}
}

func createLocalUserHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	username := utils.StringFromMap(params, "username")
	if username == "" {
		return registry.ErrorResult("validation error: missing required field: username"), nil
	}

	fullName := utils.StringFromMap(params, "full_name")
	if fullName == "" {
		return registry.ErrorResult("validation error: missing required field: full_name"), nil
	}

	email := utils.StringFromMap(params, "email")
	if email == "" {
		return registry.ErrorResult("validation error: missing required field: email"), nil
	}

	password, err := generateRandomPassword()
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to generate password: %v", err)), nil
	}

	user := &userstore.LocalUser{
		Principal: username,
		FullName:  fullName,
		Email:     email,
		Password: userstore.LocalUserPassword{
			Password: password,
		},
		PasswordChangeRequired: true,
	}

	identifier, err := userstore.New(authCtx.Connector).CreateUser(user)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create local user: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}

func generateRandomPassword() (string, error) {
	b := make([]byte, randomPasswordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
