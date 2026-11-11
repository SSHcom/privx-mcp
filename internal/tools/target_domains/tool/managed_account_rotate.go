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

// ManagedAccountRotate returns the target-domain-managed-account-rotate tool definition.
func ManagedAccountRotate() registry.Tool {
	description := "Rotate the password of a managed account under a PrivX target domain. " +
		"The account must already be managed, with rotation enabled and a password policy. " +
		"The new password is not included. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	return registry.Tool{
		Name:        "target-domain-managed-account-rotate",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: managedAccountIDSchema(),
		Handler:     rotateManagedAccountHandler,
	}
}

func rotateManagedAccountHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID, accountID, errResult := managedAccountIDs(params)
	if errResult != nil {
		return errResult, nil
	}

	client := secretsmanager.New(authCtx.Connector)
	if err := client.RotateManagedAccountPassword(domainID, accountID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to rotate managed account password: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": accountID, "rotation_started": true}), nil
}
