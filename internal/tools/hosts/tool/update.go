package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/hosts"
)

// Update returns the host-update tool definition.
//
// host-update performs a read-modify-write full PUT against the PrivX host
// store. The handler fetches the current host, overlays caller-supplied
// overrides for every editable field, and PUTs the full host back. Sensitive
// fields (passwords, certificates, host keys) and server-managed fields are
// never accepted as input but are preserved from the fetched copy. Services,
// when supplied, wholesale-replace the existing array. Principals, when
// supplied, replace the list; settings the schema does not accept, including
// command restrictions, are copied from the existing principal with the same
// name.
func Update() registry.Tool {
	description := "Update an existing PrivX host by id; only supplied fields are changed. " +
		"When provided, services wholesale-replace the existing array (omit them to preserve advanced service settings). " +
		"When provided, principals replace the list; command restrictions and other settings not in this schema stay on principals with the same name. " +
		"Does not change deployable or disabled status. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the host to update.",
		})

	// Append the shared editable-properties set after the required id so the
	// input schema lists id first.
	hosts.HostEditProperties().ForEach(func(key string, value any) {
		properties.Set(key, value)
	})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "host-update",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     updateHostHandler,
	}
}

func updateHostHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	hostID, errResult := common.RequiredPathID(params, "id")
	if errResult != nil {
		return errResult, nil
	}

	client := hoststore.New(authCtx.Connector)

	current, err := client.GetHost(hostID)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch host: %v", err)), nil
	}

	if err := hosts.PatchHost(current, params, authCtx); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdateHost(hostID, current); err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to update host: %v", err)), nil
	}

	return common.JSONResult(map[string]any{"id": hostID, "updated": true}), nil
}
