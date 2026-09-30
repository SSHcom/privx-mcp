package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/hosts"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Create returns the host-create tool definition.
//
// The tool is deliberately limited to the fields in required.md: root
// common_name/addresses plus arrays of service and principal objects. Each
// principal's roles may be supplied as role names or role UUIDs; the handler
// resolves them to full HostRole objects. Additional host details should be
// added later via the upcoming host-update tool.
func Create() registry.Tool {
	description := "Create a PrivX host with common_name, addresses, services, and principals. " +
		"Principal roles may be role names or UUIDs. Returns the created host id; use host-update for further edits. " +
		common.PresentationGuidance

	serviceItem := hosts.HostServiceItemSchema()

	principalItem := hosts.HostPrincipalItemSchema()

	properties := registry.NewOrderedMap().
		Set("common_name", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "Host common name.",
		}).
		Set("addresses", map[string]any{
			"type":        "array",
			"items":       map[string]any{"type": "string"},
			"minItems":    1,
			"description": "Host addresses (DNS names or IPs).",
		}).
		Set("services", map[string]any{
			"type":        "array",
			"minItems":    1,
			"items":       serviceItem,
			"description": "Services to create on the host.",
		}).
		Set("principals", map[string]any{
			"type":        "array",
			"minItems":    1,
			"items":       principalItem,
			"description": "Principals to create on the host.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"common_name", "addresses", "services", "principals"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "host-create",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createHostHandler,
	}
}

func createHostHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	commonName := utils.StringFromMap(params, "common_name")
	if commonName == "" {
		return registry.ErrorResult("validation error: missing required field: common_name"), nil
	}

	addresses, err := utils.ToStringSlice(params["addresses"])
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: addresses: %v", err)), nil
	}

	if len(addresses) == 0 {
		return registry.ErrorResult("validation error: addresses must contain at least one entry"), nil
	}

	servicesRaw, ok := params["services"].([]any)
	if !ok || len(servicesRaw) == 0 {
		return registry.ErrorResult("validation error: services must be a non-empty array"), nil
	}

	services, err := hosts.HostServicesFromSlice(servicesRaw)
	if err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	principalsRaw, ok := params["principals"].([]any)
	if !ok || len(principalsRaw) == 0 {
		return registry.ErrorResult("validation error: principals must be a non-empty array"), nil
	}

	principals, err := hosts.ResolvePrincipals(principalsRaw, authCtx.Connector)
	if err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	host := &hoststore.Host{
		CommonName: commonName,
		Addresses:  addresses,
		Services:   services,
		Principals: principals,
	}

	identifier, err := hoststore.New(authCtx.Connector).CreateHost(host)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to create host: %v", err)), nil
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}
