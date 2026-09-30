package tool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	apiservice "github.com/pmsshintegration/privx-mcp/internal/service/privx_api"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Create returns the request-create tool definition.
func Create() registry.Tool {
	description := "Create a GRANT access request. The authenticated user is the requester; " +
		"target_user may be someone else. " +
		common.PresentationGuidance

	roleProps := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":      "string",
			"minLength": 1,
		})

	userProps := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":      "string",
			"minLength": 1,
		})

	properties := registry.NewOrderedMap().
		Set("grant_type", map[string]any{
			"type":        "string",
			"enum":        []string{"PERMANENT", "RESTRICTED", "FLOATING"},
			"description": "PERMANENT: no time fields. RESTRICTED: grant_start/grant_end (PrivX TIME_RESTRICTED). FLOATING: floating_length.",
		}).
		Set("requested_role", map[string]any{
			"type": "object",
			"description": "From mcp-info context available-roles (already-held roles omitted). " +
				"Match grant_type and durations to that entry's grant_types, max_floating_duration (hours), and max_time_restricted_duration (days).",
			"properties":           roleProps,
			"required":             []string{"id"},
			"additionalProperties": false,
		}).
		Set("target_user", map[string]any{
			"type":                 "object",
			"description":          "Beneficiary. mcp-info user.id is the current caller.",
			"properties":           userProps,
			"required":             []string{"id"},
			"additionalProperties": false,
		}).
		Set("request_justification", map[string]any{
			"type":      "string",
			"minLength": 1,
		}).
		Set("grant_start", map[string]any{
			"type":        "string",
			"description": "RFC3339.",
		}).
		Set("grant_end", map[string]any{
			"type":        "string",
			"description": "RFC3339, after grant_start.",
		}).
		Set("floating_length", map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Hours.",
		})

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"grant_type", "requested_role", "target_user", "request_justification"}).
		Set("additionalProperties", false)

	return registry.Tool{
		Name:        "request-create",
		Description: description,
		Writes:      true,
		InputSchema: inputSchema,
		Handler:     createRequestHandler,
	}
}

func createRequestHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	justification := strings.TrimSpace(utils.StringFromMap(params, "request_justification"))
	if justification == "" {
		return registry.ErrorResult("validation error: missing required field: request_justification"), nil
	}

	grantType, err := normalizeGrantType(utils.StringFromMap(params, "grant_type"))
	if err != nil {
		return clientError(err)
	}

	role, err := objectFromParams(params, "requested_role")
	if err != nil {
		return clientError(err)
	}

	user, err := objectFromParams(params, "target_user")
	if err != nil {
		return clientError(err)
	}

	roleID := strings.TrimSpace(utils.StringFromMap(role, "id"))
	if roleID == "" {
		return registry.ErrorResult("validation error: requested_role.id is required"), nil
	}

	userID := strings.TrimSpace(utils.StringFromMap(user, "id"))
	if userID == "" {
		return registry.ErrorResult("validation error: target_user.id is required"), nil
	}

	req := &workflow.AccessRequest{
		Action:               "GRANT",
		GrantType:            grantType,
		RequestJustification: justification,
	}

	if err := applyGrantFields(req, grantType, params); err != nil {
		return clientError(err)
	}

	requestable, err := validateRequestableRoleGrant(authCtx.Connector, roleID, grantType, req)
	if err != nil {
		return clientError(err)
	}

	req.RequestedRole = &workflow.WorkflowRole{ID: requestable.ID, Name: requestable.Name}
	req.TargetUser = &workflow.WorkflowUser{ID: userID}

	client := workflow.New(authCtx.Connector)

	identifier, err := client.CreateRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}

	return common.JSONResult(map[string]string{"id": identifier.ID}), nil
}

func applyGrantFields(req *workflow.AccessRequest, grantType string, params map[string]any) error {
	switch grantType {
	case "PERMANENT":
		if utils.StringFromMap(params, "grant_start") != "" ||
			utils.StringFromMap(params, "grant_end") != "" ||
			params["floating_length"] != nil {
			return validationErrorf("validation error: PERMANENT grants must not include grant_start, grant_end, or floating_length")
		}
	case "FLOATING":
		if utils.StringFromMap(params, "grant_start") != "" || utils.StringFromMap(params, "grant_end") != "" {
			return validationErrorf("validation error: FLOATING grants must not include grant_start or grant_end")
		}

		floatingLength, err := utils.IntFromMap(params, "floating_length", 0)
		if err != nil {
			return validationErrorf("validation error: %v", err)
		}

		if floatingLength < 1 {
			return validationErrorf("validation error: floating_length is required and must be at least 1 (hours)")
		}

		req.FloatingLength = int64(floatingLength)
	case "TIME_RESTRICTED":
		if params["floating_length"] != nil {
			return validationErrorf("validation error: RESTRICTED grants must not include floating_length")
		}

		grantStart := strings.TrimSpace(utils.StringFromMap(params, "grant_start"))

		grantEnd := strings.TrimSpace(utils.StringFromMap(params, "grant_end"))
		if grantStart == "" || grantEnd == "" {
			return validationErrorf("validation error: grant_start and grant_end are required for RESTRICTED grants")
		}

		start, err := time.Parse(time.RFC3339, grantStart)
		if err != nil {
			return validationErrorf("validation error: grant_start must be RFC3339: %v", err)
		}

		end, err := time.Parse(time.RFC3339, grantEnd)
		if err != nil {
			return validationErrorf("validation error: grant_end must be RFC3339: %v", err)
		}

		if !end.After(start) {
			return validationErrorf("validation error: grant_end must be after grant_start")
		}

		req.GrantStart = grantStart
		req.GrantEnd = grantEnd
	}

	return nil
}

func normalizeGrantType(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "":
		return "", validationErrorf("validation error: missing required field: grant_type")
	case "PERMANENT":
		return "PERMANENT", nil
	case "FLOATING":
		return "FLOATING", nil
	case "RESTRICTED":
		// PrivX wire value for day-bounded grants.
		return "TIME_RESTRICTED", nil
	default:
		return "", validationErrorf(
			`validation error: invalid grant_type %q; must be PERMANENT, RESTRICTED, or FLOATING`,
			raw,
		)
	}
}

func findRequestableRole(connector restapi.Connector, roleID string) (*apiservice.RequestableRole, error) {
	roles, err := apiservice.NewWorkflowService(connector).ListAllRequestableRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to list requestable roles: %w", err)
	}

	for i := range roles {
		if roles[i].ID == roleID {
			return &roles[i], nil
		}
	}

	return nil, nil
}

func validateRequestableRoleGrant(
	connector restapi.Connector,
	roleID, grantType string,
	req *workflow.AccessRequest,
) (*apiservice.RequestableRole, error) {
	role, err := findRequestableRole(connector, roleID)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, validationErrorf("validation error: role %q is not requestable via workflow", roleID)
	}

	if !grantTypeAllowed(role.GrantTypes, grantType) {
		return nil, validationErrorf(
			"validation error: grant_type %s is not allowed for role %q; allowed: %s",
			publicGrantType(grantType),
			role.Name,
			strings.Join(publicGrantTypes(role.GrantTypes), ", "),
		)
	}

	switch grantType {
	case "FLOATING":
		if role.MaxFloatingDuration > 0 && req.FloatingLength > role.MaxFloatingDuration {
			return nil, validationErrorf(
				"validation error: floating_length must be at most %d (hours) for role %q",
				role.MaxFloatingDuration,
				role.Name,
			)
		}
	case "TIME_RESTRICTED":
		if role.MaxTimeRestrictedDuration > 0 {
			start, err := time.Parse(time.RFC3339, req.GrantStart)
			if err != nil {
				return nil, validationErrorf("validation error: grant_start must be RFC3339: %v", err)
			}

			end, err := time.Parse(time.RFC3339, req.GrantEnd)
			if err != nil {
				return nil, validationErrorf("validation error: grant_end must be RFC3339: %v", err)
			}

			maxSpan := time.Duration(role.MaxTimeRestrictedDuration) * 24 * time.Hour
			if end.Sub(start) > maxSpan {
				return nil, validationErrorf(
					"validation error: RESTRICTED grant span must be at most %d days for role %q",
					role.MaxTimeRestrictedDuration,
					role.Name,
				)
			}
		}
	}

	return role, nil
}

func grantTypeAllowed(allowed []string, grantType string) bool {
	for _, gt := range allowed {
		if gt == grantType {
			return true
		}
	}

	return false
}

func publicGrantType(grantType string) string {
	if grantType == "TIME_RESTRICTED" {
		return "RESTRICTED"
	}

	return grantType
}

func publicGrantTypes(grantTypes []string) []string {
	out := make([]string, 0, len(grantTypes))
	for _, gt := range grantTypes {
		out = append(out, publicGrantType(gt))
	}

	return out
}

func objectFromParams(params map[string]any, key string) (map[string]any, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, validationErrorf("validation error: missing required field: %s", key)
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, validationErrorf("validation error: %s must be an object", key)
	}

	return obj, nil
}

// validationError is a client-visible input failure. Operational errors
// (API/network) are returned as wrapped Go errors for runtime classification.
type validationError struct {
	msg string
}

func (e *validationError) Error() string {
	return e.msg
}

func validationErrorf(format string, args ...any) error {
	return &validationError{msg: fmt.Sprintf(format, args...)}
}

func clientError(err error) (*registry.ToolResult, error) {
	var verr *validationError
	if errors.As(err, &verr) {
		return registry.ErrorResult(err.Error()), nil
	}

	return nil, err
}
