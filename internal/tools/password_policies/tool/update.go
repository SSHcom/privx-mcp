package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/password_policies"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Update returns the password-policy-update tool definition.
func Update() registry.Tool {
	description := "Update a PrivX password policy by ID. " +
		"This is a full replacement update. " +
		"Always fetch the current state with password-policy-get first to avoid overwriting fields. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the password policy to update.",
		}).
		Set("name", map[string]any{
			"type":        "string",
			"description": "Policy name.",
		}).
		Set("max_versions", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Maximum number of password versions to retain.",
		}).
		Set("rotation_interval", map[string]any{
			"type":        "string",
			"description": "How often to rotate the password (ISO 8601 duration, e.g. \"P30D\").",
		}).
		Set("password_min_length", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Minimum password length.",
		}).
		Set("password_max_length", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Maximum password length.",
		}).
		Set("use_special_characters", map[string]any{
			"type":        "boolean",
			"description": "Include special characters in generated passwords.",
		}).
		Set("use_lower_case", map[string]any{
			"type":        "boolean",
			"description": "Include lowercase letters in generated passwords.",
		}).
		Set("use_upper_case", map[string]any{
			"type":        "boolean",
			"description": "Include uppercase letters in generated passwords.",
		}).
		Set("use_numbers", map[string]any{
			"type":        "boolean",
			"description": "Include numbers in generated passwords.",
		}).
		Set("number_of_retries", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Number of rotation retry attempts on failure.",
		}).
		Set("retry_interval", map[string]any{
			"type":        "string",
			"description": "Interval between retries (ISO 8601 duration, e.g. \"PT5M\").",
		}).
		Set("max_concurrent_checkouts", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Maximum number of concurrent password checkouts.",
		}).
		Set("max_checkout_duration", map[string]any{
			"type":        "string",
			"description": "Maximum checkout duration (ISO 8601 duration, e.g. \"PT1H\").",
		}).
		Set("rotate_on_release", map[string]any{
			"type":        "boolean",
			"description": "Rotate password when all checkouts are released.",
		}).
		Set("verify_after_rotation", map[string]any{
			"type":        "boolean",
			"description": "Verify the new password works after rotation.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "password-policy-update",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     updateHandler,
	}
}

func updateHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	policyID := utils.StringFromMap(params, "id")
	if policyID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	// Fetch current state for full replacement.
	current, err := client.GetPasswordPolicy(policyID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch password policy: %v", err)), nil
	}

	if err := password_policies.ApplyPasswordPolicyFields(current, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdatePasswordPolicy(policyID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update password policy: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": policyID, "updated": true}), nil
}
