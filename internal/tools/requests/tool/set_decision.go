package tool

import (
	"context"
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

const (
	decisionWaiting  = "WAITING"
	decisionApproved = "APPROVED"
	decisionDenied   = "DENIED"
)

// SetDecision returns the request-set-decision tool definition.
func SetDecision() registry.Tool {
	description := "Approve or deny a WAITING PrivX access request. " +
		"Each step is an approval gate that a user holding a specific role must APPROVE or DENY " +
		"(optional comment). Pass request id and 0-based step index. " +
		"If id or step is unknown, use request-search with the user's username/email in search.keywords " +
		"(e.g. filter=ACTIVE_APPROVALS), or request-list — defaults include steps and WAITING approver roles; " +
		"pass raw=true for full records. Use request-get only when you already have the request id. " +
		"Caller role eligibility is checked automatically; use mcp-info to inspect current user roles. " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the access request to decide on.",
		}).
		Set("step", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "0-based index of the approval step — a gate that must be approved or denied by a user with the step's required role.",
		}).
		Set("decision", map[string]any{
			"type":        "string",
			"enum":        []string{decisionApproved, decisionDenied},
			"description": "Decision for the step: APPROVED or DENIED.",
		}).
		Set("comment", map[string]any{
			"type":        "string",
			"description": "Optional comment attached to the decision.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "step", "decision"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "request-set-decision",
		Description: description,
		Writes:      false,
		InputSchema: inputSchema,
		Handler:     setRequestDecisionHandler,
	}
}

func setRequestDecisionHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	requestID := strings.TrimSpace(utils.StringFromMap(params, "id"))
	if requestID == "" {
		return registry.ErrorResult("validation error: missing required field: id"), nil
	}

	if _, ok := params["step"]; !ok {
		return registry.ErrorResult("validation error: missing required field: step"), nil
	}

	step, err := utils.IntFromMap(params, "step", 0)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("validation error: %v", err)), nil
	}

	if step < 0 {
		return registry.ErrorResult("validation error: step must be >= 0"), nil
	}

	decision, err := normalizeDecision(utils.StringFromMap(params, "decision"))
	if err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	comment := utils.StringFromMap(params, "comment")

	client := workflow.New(authCtx.Connector)

	request, err := client.GetRequest(requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access request: %w", err)
	}

	if err := preflightDecision(authCtx, request, step); err != nil {
		return registry.ErrorResult(err.Error()), nil
	}

	if err := client.UpdateDecisionOnRequest(requestID, workflow.Decision{
		Step:     step,
		Decision: decision,
		Comment:  comment,
	}); err != nil {
		return nil, fmt.Errorf("failed to set request decision: %w", err)
	}

	return common.JSONResult(map[string]any{
		"id":       requestID,
		"step":     step,
		"decision": decision,
	}), nil
}

func normalizeDecision(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return "", fmt.Errorf("validation error: missing required field: decision")
	case decisionApproved, decisionDenied:
		return strings.TrimSpace(raw), nil
	default:
		return "", fmt.Errorf(
			`validation error: invalid decision %q; must be APPROVED or DENIED`,
			raw,
		)
	}
}

func preflightDecision(authCtx *auth.AuthContext, request *workflow.AccessRequest, step int) error {
	if request == nil {
		return fmt.Errorf("validation error: access request not found")
	}

	if !strings.EqualFold(strings.TrimSpace(request.Status), decisionWaiting) {
		return fmt.Errorf(
			"validation error: access request status must be WAITING to set a decision (got %q)",
			request.Status,
		)
	}

	if step < 0 || step >= len(request.Steps) {
		return fmt.Errorf(
			"validation error: step %d is out of range (request has %d step(s))",
			step, len(request.Steps),
		)
	}

	stepRec := request.Steps[step]

	var waitingRoles []workflow.WorkflowRole

	for _, approver := range stepRec.Approvers {
		if strings.EqualFold(strings.TrimSpace(approver.Decision), decisionWaiting) {
			waitingRoles = append(waitingRoles, approver.Role)
		}
	}

	if len(waitingRoles) == 0 {
		return fmt.Errorf("validation error: step %d has no WAITING approver decisions", step)
	}

	for _, role := range waitingRoles {
		if authCtx.HasRole(role.Name, role.ID) {
			return nil
		}
	}

	return fmt.Errorf("authorization error: missing required approver role for this step")
}
