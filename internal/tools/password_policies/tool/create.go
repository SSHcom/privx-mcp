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

// Create returns the password-policy-create tool definition.
func Create() registry.Tool {
	description := "Create a new PrivX password policy. " +
		"Name and max_versions are required. " +
		"Duration fields use ISO 8601 format (e.g. P30D=30 days, PT1H=1 hour, PT5M=5 minutes). " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("name", map[string]any{
			"type":        "string",
			"minLength":   1,
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
		Set("required", []string{"name", "max_versions"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "password-policy-create",
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

	maxVersions, err := utils.IntFromMap(params, "max_versions", 0)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: max_versions: %v", err)), nil
	}

	if maxVersions < 1 {
		return registry.ErrorResult("validation error: missing or invalid required field: max_versions"), nil
	}

	policy := &secretsmanager.PasswordPolicy{
		Name:                   name,
		MaxVersions:            maxVersions,
		RotationInterval:       "P1M",
		PasswordMinLength:      20,
		PasswordMaxLength:      20,
		UseSpecialCharacters:   true,
		UseLowercase:           true,
		UseUppercase:           true,
		UseNumbers:             true,
		NumberOfRetries:        5,
		RetryInterval:          "PT5M",
		MaxConcurrentCheckouts: 1,
		MaxCheckoutDuration:    "PT10M",
		RotateOnRelease:        false,
		VerifyAfterRotation:    false,
	}

	if err := password_policies.ApplyPasswordPolicyFields(policy, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	identifier, err := client.CreatePasswordPolicy(policy)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create password policy: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
