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

// Scan returns the target-domain-scan tool definition.
func Scan() registry.Tool {
	description := "Scan a PrivX target domain by id. " +
		"Asks PrivX to read accounts from the domain endpoints. " +
		"If the basis for a scan is not fulfilled, PrivX returns HTTP 400 Bad Request. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain to scan.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "target-domain-scan",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     scanTargetDomainHandler,
	}
}

func scanTargetDomainHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID := utils.StringFromMap(params, "id")
	if domainID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	// POST .../targetdomains/{id}/scan 404s on this PrivX. RefreshTargetDomain posts to .../refresh.
	client := secretsmanager.New(authCtx.Connector)
	if err := client.RefreshTargetDomain(domainID); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to scan target domain: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": domainID, "scan_started": true}), nil
}
