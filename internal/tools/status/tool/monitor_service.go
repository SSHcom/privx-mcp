package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// MonitorService returns the status-monitor-service tool definition.
func MonitorService() registry.Tool {
	description := "Get monitor-service microservice status. " +
		common.PresentationGuidance

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", registry.NewOrderedMap()).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "status-monitor-service",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     monitorServiceStatusHandler,
	}
}

func monitorServiceStatusHandler(ctx context.Context, _ map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	client := monitor.New(authCtx.Connector)

	svcStatus, err := client.Status()
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch monitor-service status: %v", err)), nil
	}

	return common.JSONResult(svcStatus), nil
}
