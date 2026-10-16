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

// Create returns the target-domain-create tool definition.
func Create() registry.Tool {
	description := "Create a PrivX target domain. " +
		"A domain needs at least one AD/LDAP or Entra endpoint, scan priorities must be unique, " +
		"and at least one endpoint is used for password rotation. " +
		"An AD/LDAP endpoint requires ldap_bind_password; PrivX rejects the create when it is missing. " +
		"This does not create a managed account. " +
		"Find a scanned account with target-domain-account-search, then use target-domain-managed-account-create. " +
		"This call does not attach an account to a host. " +
		"Returns the created domain id. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", target_domains.DomainFieldProperties()).
		Set("required", []string{"name", "domain_name", "endpoints"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "target-domain-create",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     createTargetDomainHandler,
	}
}

func createTargetDomainHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	if utils.StringFromMap(params, "name") == "" {
		return registry.ErrorResult("validation error: missing required field: name"), nil
	}

	if utils.StringFromMap(params, "domain_name") == "" {
		return registry.ErrorResult("validation error: missing required field: domain_name"), nil
	}

	if _, ok := params["endpoints"]; !ok {
		return registry.ErrorResult("validation error: missing required field: endpoints"), nil
	}

	domain := &secretsmanager.TargetDomain{}
	if err := target_domains.ApplyTargetDomainFields(domain, params); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	client := secretsmanager.New(authCtx.Connector)

	identifier, err := client.CreateTargetDomain(domain)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create target domain: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
