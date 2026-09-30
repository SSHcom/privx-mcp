package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
)

// rateLimitExceededMessage is returned to MCP clients when a caller exceeds
// the configured per-identity tool-call quota.
const rateLimitExceededMessage = "Too many requests. Please try again later."

// filterListedTools narrows tools/list to those the caller is authorised to
// invoke. Visibility mirrors the call-time auth middleware so a client never
// sees a tool it cannot call.
func (c *Core) filterListedTools(ctx context.Context, tools []*mcp.Tool) []*mcp.Tool {
	claims := c.claimsSource.ListClaims(ctx)
	return c.filterByPermissions(ctx, claims, tools)
}

func (c *Core) filterByPermissions(ctx context.Context, identity *oauth.IdentityClaims, tools []*mcp.Tool) []*mcp.Tool {
	// Resolve the PrivX user context at most once for the whole tools/list
	// pass. Per-tool checks then reuse that result instead of re-querying
	// PrivX (and re-logging) for every registered tool.
	var (
		resolved      *rolestore.User
		resolveTried  bool
		resolveFailed bool
		resolveErr    error
	)

	ensureResolved := func() *rolestore.User {
		if resolveTried {
			if resolveFailed {
				return nil
			}

			return resolved
		}

		resolveTried = true

		user, err := c.permissions.ResolveUserContext(ctx, identity)
		if err != nil {
			resolveFailed = true
			resolveErr = err
			logging.Info(
				"tools/list permission resolution failed",
				"email", identityEmail(identity),
				"upn", identityUPN(identity),
				"err", err,
			)

			return nil
		}

		resolved = user

		userID := ""
		if user != nil {
			userID = user.ID
		}

		logging.Debug(
			"tools/list permission context resolved",
			"email", identityEmail(identity),
			"upn", identityUPN(identity),
			"user_id", userID,
			"roles", roleNames(user),
			"permissions", resolvedPermissions(user),
		)

		return resolved
	}

	filtered := make([]*mcp.Tool, 0, len(tools))
	hidden := 0

	for _, tool := range tools {
		if tool == nil {
			hidden++
			continue
		}

		registeredTool, ok := c.registry.Get(tool.Name)
		if !ok {
			hidden++
			continue
		}

		required := registeredTool.RequiredPermissions

		var roles *rolestore.User
		if identity != nil && requiresPrivXResolution(required) {
			roles = ensureResolved()
		}

		if AllowResolved(identity, roles, required) {
			filtered = append(filtered, tool)
			continue
		}

		hidden++
	}

	logging.Info(
		"tools/list permission resolution",
		"email", identityEmail(identity),
		"upn", identityUPN(identity),
		"input", len(tools),
		"visible", len(filtered),
		"hidden", hidden,
		"resolve_tried", resolveTried,
		"resolve_failed", resolveFailed,
		"resolve_err", resolveErr,
	)

	return filtered
}

func identityEmail(identity *oauth.IdentityClaims) string {
	if identity == nil {
		return ""
	}

	return identity.Email
}

func identityUPN(identity *oauth.IdentityClaims) string {
	if identity == nil {
		return ""
	}

	return identity.UPN
}

func roleNames(user *rolestore.User) []string {
	if user == nil {
		return nil
	}

	names := make([]string, 0, len(user.Roles))
	for _, role := range user.Roles {
		names = append(names, role.Name)
	}

	return names
}

// activeRoles returns PrivX roles that are active at the current instant
// (role time windows applied). Used to populate AuthContext.Roles for
// handler-side membership checks; independent of permission-scope gating.
func activeRoles(user *rolestore.User) []auth.Role {
	return activeRolesAt(user, time.Now())
}

func activeRolesAt(user *rolestore.User, at time.Time) []auth.Role {
	if user == nil {
		return nil
	}

	roles := make([]auth.Role, 0, len(user.Roles))
	for _, role := range user.Roles {
		if role.ID == "" && role.Name == "" {
			continue
		}

		if !isRoleWindowAllowed(at, role.Name, role.Context) {
			continue
		}

		roles = append(roles, auth.Role{ID: role.ID, Name: role.Name})
	}

	return roles
}

func (c *Core) authMiddleware(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		toolName := callToolName(request)

		claims := c.claimsSource.ToolCallClaims(ctx)
		if claims == nil {
			logging.Info(
				"tool call rejected",
				"tool", toolName,
				"reason", "no-claims",
				"msg", c.claimsSource.MissingClaimsMessage(),
			)

			return errorCallResult(c.claimsSource.MissingClaimsMessage()), nil
		}

		if c.rateLimiter != nil && !c.rateLimiter.Allow(c.sessionBaseURL, claims) {
			logging.Info(
				"tool call rate limited",
				"tool", toolName,
				"email", claims.Email,
				"upn", claims.UPN,
			)

			return errorCallResult(rateLimitExceededMessage), nil
		}

		authCtx, err := c.auth.Authenticate(ctx, claims)
		if err != nil {
			logging.Error(
				"tool call authentication failed",
				"tool", toolName,
				"err", err,
			)
			result := ToMCPError(err)

			return toCallToolResult(result, false, toolName), nil
		}

		if err := c.bindIssuerSubject(authCtx, claims); err != nil {
			logging.Warn(
				"issuer subject binding rejected",
				"tool", toolName,
				"user", usernameFromAuth(authCtx),
				"issuer", claims.Issuer,
				"subject", claims.Subject,
				"err", err,
			)

			return errorCallResult("authentication failed: " + err.Error()), nil
		}

		tool, ok := c.registry.Get(toolName)
		if !ok {
			result := ToMCPError(&AuthorizationError{ToolName: toolName})
			return toCallToolResult(result, false, toolName), nil
		}

		decision := c.permissions.IsAllowed(ctx, claims, tool.RequiredPermissions)
		logAuthorizationDecision(toolName, claims, tool.RequiredPermissions, decision.Allowed)

		if decision.Refreshed {
			c.notifyToolsListChanged(ctx)
		}

		if !decision.Allowed {
			result := ToMCPError(&AuthorizationError{ToolName: toolName})
			if decision.Resolved {
				result = scopeDeniedToolResult(toolName, decision.RolesChanged)
			}

			return toCallToolResult(result, false, toolName), nil
		}

		// After permission gating, copy user ID and active roles onto
		// AuthContext for handler-side checks. Resolve hits the session cache
		// when IsAllowed already resolved the user; failure leaves UserID/Roles
		// empty (allowed authenticated-only tools still proceed).
		if resolved, resolveErr := c.permissions.ResolveUserContext(ctx, claims); resolveErr == nil && resolved != nil {
			authCtx.UserID = resolved.ID
			authCtx.Roles = activeRoles(resolved)

			match, err := c.currentUserMatchesResolvedUser(claims, authCtx, resolved)
			if err != nil {
				logging.Error(
					"connector identity binding check failed",
					"tool", toolName,
					"mapped_username", authCtx.Username,
					"resolved_user_id", resolved.ID,
					"resolved_principal", resolved.Principal,
					"resolved_source_type", resolved.SourceType,
					"err", err,
				)

				return errorCallResult("authentication failed: unable to verify connector identity"), nil
			}

			if !match {
				logging.Warn(
					"connector identity mismatch",
					"tool", toolName,
					"mapped_username", authCtx.Username,
					"resolved_user_id", resolved.ID,
					"resolved_principal", resolved.Principal,
					"resolved_source_type", resolved.SourceType,
				)

				return errorCallResult("authentication failed: connector user does not match authorized user"), nil
			}
		}

		ctx = auth.NewContext(ctx, authCtx)

		return next(ctx, request)
	}
}

func (c *Core) currentUserMatchesResolvedUser(
	claims *oauth.IdentityClaims,
	authCtx *auth.AuthContext,
	resolved *rolestore.User,
) (bool, error) {
	if authCtx == nil || resolved == nil || authCtx.Connector == nil {
		return true, nil
	}

	if cachedID, ok := c.cachedConnectorUserID(claims, resolved.ID); ok {
		logging.Info(
			"connector identity binding check",
			"check", "cached",
			"mapped_username", authCtx.Username,
			"resolved_user_id", resolved.ID,
			"resolved_principal", resolved.Principal,
			"resolved_source_type", resolved.SourceType,
			"connector_user_id", cachedID,
		)

		return true, nil
	}

	client := rolestore.New(authCtx.Connector)

	currentRaw, err := client.GetCurrentUserInfo()
	if err != nil {
		return false, fmt.Errorf("fetch current user: %w", err)
	}

	if currentRaw == nil {
		return false, fmt.Errorf("fetch current user: empty response")
	}

	current := &rolestore.User{}
	if err := json.Unmarshal([]byte(*currentRaw), current); err != nil {
		return false, fmt.Errorf("decode current user response: %w", err)
	}

	logging.Info(
		"connector identity binding check",
		"mapped_username", authCtx.Username,
		"resolved_user_id", resolved.ID,
		"resolved_principal", resolved.Principal,
		"resolved_source_type", resolved.SourceType,
		"connector_user_id", current.ID,
		"connector_principal", current.Principal,
		"connector_source_type", current.SourceType,
	)

	if strings.TrimSpace(current.ID) == "" || strings.TrimSpace(resolved.ID) == "" {
		return false, fmt.Errorf("missing user ID in identity binding check")
	}

	match := strings.EqualFold(strings.TrimSpace(current.ID), strings.TrimSpace(resolved.ID))
	if match {
		c.storeConnectorUserID(claims, resolved, current.ID)
	}

	return match, nil
}

func (c *Core) cachedConnectorUserID(claims *oauth.IdentityClaims, resolvedUserID string) (string, bool) {
	if c == nil || c.permissions == nil || c.permissions.sessionService == nil {
		return "", false
	}

	cached, ok := c.permissions.sessionService.Get(c.permissions.sessionBaseURL, claims)
	if !ok {
		return "", false
	}

	if !strings.EqualFold(strings.TrimSpace(cached.UserID), strings.TrimSpace(resolvedUserID)) {
		return "", false
	}

	connectorUserID := strings.TrimSpace(cached.ConnectorUserID)
	if connectorUserID == "" {
		return "", false
	}

	return connectorUserID, true
}

func (c *Core) bindIssuerSubject(authCtx *auth.AuthContext, claims *oauth.IdentityClaims) error {
	if c != nil && c.permissions != nil && c.permissions.sessionService != nil {
		return c.permissions.sessionService.BindIssuerSubject(
			c.permissions.sessionBaseURL,
			usernameFromAuth(authCtx),
			claims,
		)
	}

	return session.ValidateIssuerSubject(claims)
}

func usernameFromAuth(authCtx *auth.AuthContext) string {
	if authCtx == nil {
		return ""
	}

	return authCtx.Username
}

func (c *Core) storeConnectorUserID(claims *oauth.IdentityClaims, resolved *rolestore.User, connectorUserID string) {
	if c == nil || c.permissions == nil || c.permissions.sessionService == nil || resolved == nil {
		return
	}

	c.permissions.sessionService.Set(
		c.permissions.sessionBaseURL,
		claims,
		session.CachedUserContext{
			UserID:          resolved.ID,
			ResolvedRoles:   resolved,
			ConnectorUserID: connectorUserID,
		},
	)
}

// logAuthorizationDecision records the per-call authorization outcome with the
// resolved identity, so tool invocations are traceable to a caller. The required
// permissions and the boolean decision are included for at-a-glance auditing.
func logAuthorizationDecision(toolName string, identity *oauth.IdentityClaims, required []string, allowed bool) {
	decision := "denied"
	if allowed {
		decision = "allowed"
	}

	logging.Info(
		"tool call authorization",
		"tool", toolName,
		"decision", decision,
		"email", identity.Email,
		"upn", identity.UPN,
		"required", required,
	)
}

func callToolName(request *mcp.CallToolRequest) string {
	if request == nil || request.Params == nil {
		return ""
	}

	return request.Params.Name
}

func (c *Core) notifyToolsListChanged(context.Context) {
	// The official SDK broadcasts notifications/tools/list_changed only when
	// the process-wide tool set changes (AddTool/RemoveTools). ServerSession
	// has no public API to notify a single calling session after a PrivX role
	// refresh. Callers still get the roles_changed / restart_host_application
	// error payload.
	logging.Debug("skipping per-session tools/list_changed; official MCP Go SDK cannot notify one session")
}

const scopeDeniedRestartMessage = "If your PrivX roles have changed, fully quit and reopen this application to refresh the available tools. Restarting only the MCP connection is not enough in some clients."

type scopeDeniedPayload struct {
	Error   string `json:"error"`
	Tool    string `json:"tool"`
	Message string `json:"message"`
	Action  string `json:"action"`
}

func scopeDeniedToolResult(toolName string, rolesChanged bool) *registry.ToolResult {
	code := "not_authorized"
	if rolesChanged {
		code = "roles_changed"
	}

	raw, err := json.Marshal(scopeDeniedPayload{
		Error:   code,
		Tool:    toolName,
		Message: fmt.Sprintf("You are not authorized to invoke %s. %s", toolName, scopeDeniedRestartMessage),
		Action:  "restart_host_application",
	})
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf(
			"You are not authorized to invoke %s. %s",
			toolName,
			scopeDeniedRestartMessage,
		))
	}

	return registry.ErrorResult(string(raw))
}
