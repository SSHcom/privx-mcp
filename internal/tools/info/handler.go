package info

import (
	"context"
	"fmt"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	apiservice "github.com/pmsshintegration/privx-mcp/internal/service/privx_api"
	"github.com/pmsshintegration/privx-mcp/internal/service/security"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

type roleInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userInfo struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Roles []roleInfo `json:"roles"`
}

func infoHandler(snapshot InstanceSnapshot) registry.ToolHandler {
	return func(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
		contextKeysReq, err := optionalStringKeys(params, "context")
		if err != nil {
			return registry.ErrorResult(err.Error()), nil
		}

		resourceKeysReq, err := optionalStringKeys(params, "resources")
		if err != nil {
			return registry.ErrorResult(err.Error()), nil
		}

		out := map[string]any{}

		authCtx := auth.FromContext(ctx)
		if authCtx == nil {
			return registry.ErrorResult("authentication error: missing auth context"), nil
		}

		roles := make([]roleInfo, 0, len(authCtx.Roles))
		for _, role := range authCtx.Roles {
			roles = append(roles, roleInfo{ID: role.ID, Name: role.Name})
		}

		caller := userInfo{
			ID:    authCtx.UserID,
			Name:  authCtx.Username,
			Roles: roles,
		}
		if term, blocked := prepareUser(&caller); blocked {
			logging.Warn("blocked tool call output", "type", toolName, "term", term)
			return registry.ErrorResult(security.OutputRejectedMessage()), nil
		}

		out["user"] = caller
		out["privx"] = snapshot.toPrivXInfo()

		if len(contextKeysReq) > 0 {
			loaded, err := loadContext(contextKeysReq)
			if err != nil {
				return clientOrOpError(err)
			}

			if resolvedContains(contextKeysReq, contextKeyAvailableRoles) {
				available, err := loadAvailableRoles(authCtx)
				if err != nil {
					return clientOrOpError(err)
				}

				if term, blocked := prepareRequestableRoles(available); blocked {
					logging.Warn("blocked tool call output", "type", toolName, "term", term)
					return registry.ErrorResult(security.OutputRejectedMessage()), nil
				}

				loaded[contextKeyAvailableRoles] = available
			}

			out["context"] = loaded
		}

		if len(resourceKeysReq) > 0 {
			loaded, err := loadResources(resourceKeysReq)
			if err != nil {
				return clientOrOpError(err)
			}

			out["resources"] = loaded
		}

		return common.JSONResult(out), nil
	}
}

// clientOrOpError keeps validation and auth messages as tool results so the
// caller sees them, and returns operational failures for runtime classification.
func clientOrOpError(err error) (*registry.ToolResult, error) {
	if strings.HasPrefix(err.Error(), "failed to ") {
		return nil, err
	}

	return registry.ErrorResult(err.Error()), nil
}

// mcp-info is a trusted tool, so the runtime does not inspect its payload. The
// caller name and role names below come from PrivX and are user-controlled, so
// they are sanitized and blacklist-checked here instead.
func prepareUser(caller *userInfo) (string, bool) {
	if term, blocked := security.PrepareStrings(security.DefaultOverrides["principal"], &caller.Name); blocked {
		return term, true
	}

	for i := range caller.Roles {
		if term, blocked := security.PrepareStrings(security.DefaultOverrides["name"], &caller.Roles[i].Name); blocked {
			return term, true
		}
	}

	return "", false
}

func prepareRequestableRoles(roles []apiservice.RequestableRole) (string, bool) {
	for i := range roles {
		if term, blocked := security.PrepareStrings(security.DefaultOverrides["name"], &roles[i].Name); blocked {
			return term, true
		}
	}

	return "", false
}

func loadAvailableRoles(authCtx *auth.AuthContext) ([]apiservice.RequestableRole, error) {
	if authCtx == nil || authCtx.Connector == nil {
		return nil, fmt.Errorf("authentication error: missing PrivX connector in context")
	}

	roles, err := apiservice.NewWorkflowService(authCtx.Connector).ListAllRequestableRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to list available roles: %w", err)
	}

	return filterHeldRoles(roles, authCtx.Roles), nil
}

func filterHeldRoles(roles []apiservice.RequestableRole, held []auth.Role) []apiservice.RequestableRole {
	heldIDs := make(map[string]struct{}, len(held))
	for _, r := range held {
		if r.ID == "" {
			continue
		}

		heldIDs[r.ID] = struct{}{}
	}

	out := make([]apiservice.RequestableRole, 0, len(roles))
	for _, role := range roles {
		if _, ok := heldIDs[role.ID]; ok {
			continue
		}

		out = append(out, role)
	}

	return out
}

func optionalStringKeys(params map[string]any, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil, nil
	}

	keys, err := utils.ToStringSlice(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be an array of strings: %w", key, err)
	}

	return keys, nil
}
