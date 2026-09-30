package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// Codes returns the audit-event-codes tool definition.
func Codes() registry.Tool {
	description := "List PrivX audit event codes with names and descriptions. " +
		"Use to look up event_id / event_name when interpreting audit-event-list or audit-event-search results. " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", registry.NewOrderedMap()).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "audit-event-codes",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     auditEventCodesHandler,
	}
}

func auditEventCodesHandler(ctx context.Context, _ map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	client := monitor.New(authCtx.Connector)

	codes, err := client.GetAuditEventCodes()
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch audit event codes: %v", err)), nil
	}

	return common.JSONResult(codes), nil
}
