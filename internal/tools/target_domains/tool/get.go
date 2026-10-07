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

// Get returns the target-domain-get tool definition.
func Get() registry.Tool {
	description := "Get a single PrivX target domain by ID. Credential fields are omitted. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain to fetch.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"})

	return registry.Tool{
		Name:        "target-domain-get",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     getTargetDomainHandler,
	}
}

func getTargetDomainHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID := utils.StringFromMap(params, "id")
	if domainID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	domain, err := client.GetTargetDomain(domainID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch target domain: %v", err)), nil
	}

	return common.JSONResult(target_domains.FormatTargetDomain(domain)), nil
}
