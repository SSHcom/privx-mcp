package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/target_domains"
)

// ManagedAccountDelete returns the target-domain-managed-account-delete tool definition.
func ManagedAccountDelete() registry.Tool {
	description := "Stop PrivX from managing one account under a target domain. " +
		"The directory user stays in the domain. " +
		"Pass the managed account id. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	return registry.Tool{
		Name:        "target-domain-managed-account-delete",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: managedAccountIDSchema(),
		Handler:     deleteManagedAccountHandler,
	}
}

func deleteManagedAccountHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID, accountID, errResult := managedAccountIDs(params)
	if errResult != nil {
		return errResult, nil
	}

	client := secretsmanager.New(authCtx.Connector)
	if err := client.DeleteManagedAccount(domainID, accountID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to delete managed account: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": accountID, "deleted": true}), nil
}
