package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/target_domains"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// ManagedAccountUpdate returns the target-domain-managed-account-update tool definition.
func ManagedAccountUpdate() registry.Tool {
	description := "Update management flags on a managed account under a PrivX target domain. " +
		"Always fetch the current state with target-domain-managed-account-get first. " +
		"Omitted fields stay as fetched. An empty string does not clear comment or password_policy_id. " +
		"This does not rename the directory user or set a password. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain that owns the managed account.",
		}).
		Set("account_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the managed account to update.",
		}).
		Set("enabled", map[string]any{
			"type":        "boolean",
			"description": "Whether the managed account is enabled.",
		}).
		Set("rotation_enabled", map[string]any{
			"type":        "boolean",
			"description": "Whether password rotation is enabled.",
		}).
		Set("explicit_checkout", map[string]any{
			"type":        "boolean",
			"description": "Product switch that allows copying the password.",
		}).
		Set("disable_rdp_cert_auth", map[string]any{
			"type":        "boolean",
			"description": "Whether RDP certificate authentication is disabled.",
		}).
		Set("password_policy_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Password policy id. An empty string does not clear the current policy.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Comment stored on the managed account. An empty string does not clear it.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "account_id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "target-domain-managed-account-update",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     updateManagedAccountHandler,
	}
}

func updateManagedAccountHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID := utils.StringFromMap(params, "id")
	if domainID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	accountID := utils.StringFromMap(params, "account_id")
	if accountID == "" {
		return registry.ErrorResult("validation error: missing required field: account_id"), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	current, err := client.GetManagedAccount(domainID, accountID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch managed account: %v", err)), nil
	}

	if err := target_domains.ApplyManagedAccountFields(current, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdateTargetManagedAccount(domainID, accountID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update managed account: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": accountID, "updated": true}), nil
}
