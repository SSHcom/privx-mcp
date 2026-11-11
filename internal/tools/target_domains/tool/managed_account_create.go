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

// ManagedAccountCreate returns the target-domain-managed-account-create tool definition.
func ManagedAccountCreate() registry.Tool {
	description := "Turn one scanned directory account into a managed account under a PrivX target domain. " +
		"Pass the account id from target-domain-account-search (UNMANAGED). " +
		"This does not create a directory user. " +
		"enabled defaults to true; the other flags default to false. " +
		"password_policy_id is required when rotation_enabled or rotate is true. " +
		"rotate starts a password rotation during create and does not return the new password. " +
		"Returns the managed account id. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain that owns the scanned account.",
		}).
		Set("account_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the scanned directory account from target-domain-account-search.",
		}).
		Set("enabled", map[string]any{
			"type":        "boolean",
			"description": "Whether the managed account is enabled. Defaults to true.",
		}).
		Set("rotation_enabled", map[string]any{
			"type":        "boolean",
			"description": "Whether password rotation stays enabled. Requires password_policy_id when true. Defaults to false.",
		}).
		Set("rotate", map[string]any{
			"type":        "boolean",
			"description": "Rotate the password as part of create. The new password is not returned. Requires password_policy_id when true. Defaults to false.",
		}).
		Set("explicit_checkout", map[string]any{
			"type":        "boolean",
			"description": "Product switch that allows copying the password. Defaults to false.",
		}).
		Set("disable_rdp_cert_auth", map[string]any{
			"type":        "boolean",
			"description": "Whether RDP certificate authentication is disabled. Defaults to false.",
		}).
		Set("password_policy_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Password policy id. Required when rotation_enabled or rotate is true.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Comment stored on the managed account.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "account_id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "target-domain-managed-account-create",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     createManagedAccountHandler,
	}
}

func createManagedAccountHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID, accountID, errResult := managedAccountIDs(params)
	if errResult != nil {
		return errResult, nil
	}

	data, err := managedAccountCreateData(params)
	if err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	ids, err := client.BatchCreateManagedAccount(domainID, secretsmanager.ManagedAccountCreateBatch{
		IDs:  []string{accountID},
		Data: data,
	})
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create managed account: %v", err)), nil
	}

	createdID := accountID
	if len(ids.IDs) > 0 {
		createdID = ids.IDs[0]
	}

	return common.JSONResult(map[string]any{"id": createdID, "created": true}), nil
}

// managedAccountCreateData builds the batch-create body the PrivX UI sends
// for one scanned account. enabled defaults to true. Empty comment and an
// empty password policy are left unset.
func managedAccountCreateData(params map[string]any) (secretsmanager.ManagedAccountCreateData, error) {
	data := secretsmanager.ManagedAccountCreateData{Enabled: true}

	if _, present := params["enabled"]; present {
		enabled, _, err := utils.OverlayBool(params, "enabled")
		if err != nil {
			return data, fmt.Errorf("validation error: %w", err)
		}

		data.Enabled = enabled
	}

	flags := []struct {
		key string
		set func(bool)
	}{
		{key: "rotation_enabled", set: func(v bool) { data.RotationEnabled = v }},
		{key: "rotate", set: func(v bool) { data.Rotate = v }},
		{key: "explicit_checkout", set: func(v bool) { data.ExplicitCheckout = v }},
		{key: "disable_rdp_cert_auth", set: func(v bool) { data.DisableRDPCertAuth = v }},
	}
	for _, field := range flags {
		value, ok, err := utils.OverlayBool(params, field.key)
		if err != nil {
			return data, fmt.Errorf("validation error: %w", err)
		}

		if ok {
			field.set(value)
		}
	}

	comment, ok, err := utils.OverlayString(params, "comment")
	if err != nil {
		return data, fmt.Errorf("validation error: %w", err)
	}

	if ok && comment != "" {
		data.Comment = comment
	}

	policyID, ok, err := utils.OverlayString(params, "password_policy_id")
	if err != nil {
		return data, fmt.Errorf("validation error: %w", err)
	}

	if ok && policyID != "" {
		data.PasswordPolicy = secretsmanager.PasswordPolicyHandle{ID: policyID}
	}

	if (data.RotationEnabled || data.Rotate) && data.PasswordPolicy.ID == "" {
		return data, fmt.Errorf("validation error: password_policy_id is required when rotation_enabled or rotate is true")
	}

	return data, nil
}
