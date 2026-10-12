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

// Update returns the target-domain-update tool definition.
func Update() registry.Tool {
	description := "Update a PrivX target domain by id. " +
		"This is a full replacement update. " +
		"Always fetch the current state with target-domain-get first. " +
		"Omitted fields stay as fetched; a full replacement drops a field only when this overlay clears it. " +
		"An empty string does not clear an existing value. " +
		"When endpoints is supplied it replaces the endpoint list. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain to update.",
		})
	target_domains.DomainFieldProperties().ForEach(func(key string, value any) {
		properties.Set(key, value)
	})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "target-domain-update",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     updateTargetDomainHandler,
	}
}

func updateTargetDomainHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID := utils.StringFromMap(params, "id")
	if domainID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	current, err := client.GetTargetDomain(domainID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch target domain: %v", err)), nil
	}

	if err := target_domains.ApplyTargetDomainFields(current, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdateTargetDomain(domainID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update target domain: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": domainID, "updated": true}), nil
}
