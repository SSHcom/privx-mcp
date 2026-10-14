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

// ManagedAccountGet returns the target-domain-managed-account-get tool definition.
func ManagedAccountGet() registry.Tool {
	description := "Get a single managed account under a PrivX target domain by id. Checkout passwords are omitted. " +
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
			"description": "The id of the managed account to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "account_id"})

	return registry.Tool{
		Name:        "target-domain-managed-account-get",
		Description: description,
		Writes:      false,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     getManagedAccountHandler,
	}
}

func getManagedAccountHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
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

	account, err := client.GetManagedAccount(domainID, accountID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch managed account: %v", err)), nil
	}

	return common.JSONResult(target_domains.FormatManagedAccount(account)), nil
}
