package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	apiservice "github.com/pmsshintegration/privx-mcp/internal/service/privx_api"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
	dateutils "github.com/pmsshintegration/privx-mcp/internal/utils/date"
)

// ** Engine construction **

// PermissionEngine evaluates global tool access permissions.
type PermissionEngine struct {
	userAPI         permissionUserAPI
	sessionService  *session.Service
	sessionBaseURL  string
	sourceType      string
	refreshCooldown time.Duration
}

type userRoleResolution struct {
	user      *rolestore.User
	userID    string
	fromCache bool
}

type permissionUserAPI interface {
	SearchAllUsers(search rolestore.UserSearch) ([]rolestore.User, error)
	ResolveUserRoles(userID string) (*rolestore.User, error)
}

// PermissionEngineOption configures optional PermissionEngine dependencies.
type PermissionEngineOption func(*PermissionEngine)

// WithSessionService makes the engine reuse cached user context for the given
// PrivX base URL.
func WithSessionService(service *session.Service, baseURL string) PermissionEngineOption {
	return func(pe *PermissionEngine) {
		if pe == nil {
			return
		}

		pe.sessionService = service
		pe.sessionBaseURL = baseURL
	}
}

// WithSourceType configures which PrivX user source_type must match when
// resolving an identity to a PrivX user.
func WithSourceType(sourceType string) PermissionEngineOption {
	return func(pe *PermissionEngine) {
		if pe == nil {
			return
		}

		pe.sourceType = sourceType
	}
}

// WithRefreshCooldown sets how long to wait between on-deny PrivX role
// refreshes for the same identity. Zero disables the refresh path.
func WithRefreshCooldown(d time.Duration) PermissionEngineOption {
	return func(pe *PermissionEngine) {
		if pe == nil {
			return
		}

		pe.refreshCooldown = d
	}
}

// NewPermissionEngine creates a new PermissionEngine.
func NewPermissionEngine() *PermissionEngine {
	return &PermissionEngine{}
}

// NewPermissionEngineWithClient creates a new PermissionEngine with a PrivX API client.
func NewPermissionEngineWithClient(client restapi.Connector, options ...PermissionEngineOption) *PermissionEngine {
	engine := &PermissionEngine{}
	if client != nil {
		engine.userAPI = apiservice.NewUserService(client)
	}

	for _, option := range options {
		if option == nil {
			continue
		}

		option(engine)
	}

	return engine
}

// ** Authorization flow **

// AllowDecision is the outcome of a tool-call permission check.
type AllowDecision struct {
	Allowed      bool
	Refreshed    bool // completed on-deny PrivX refetch
	RolesChanged bool // refreshed roles or permissions differ from the cache
	Resolved     bool // PrivX user context was loaded; a deny is a missing scope
}

// IsAllowed authorizes access for an identity and a tool's requirements.
// Used for single tool-call checks. tools/list should resolve the identity
// once via ResolveUserContext and then use AllowResolved per tool.
//
// Refreshed is true only after a completed on-deny PrivX refetch (cooldown
// elapsed and roles were loaded again). Callers then return the
// roles_changed / restart_host_application payload. The official MCP Go SDK
// cannot notify a single session with tools/list_changed.
func (pe *PermissionEngine) IsAllowed(
	ctx context.Context,
	identity *oauth.IdentityClaims,
	required []string,
) AllowDecision {
	if !requiresPrivXResolution(required) {
		return AllowDecision{Allowed: AllowResolved(identity, nil, required)}
	}

	resolved, err := pe.resolveUserRoles(ctx, identity)
	if err != nil {
		return AllowDecision{}
	}

	if AllowResolved(identity, resolved.user, required) {
		return AllowDecision{Allowed: true, Resolved: true}
	}

	if !resolved.fromCache {
		return AllowDecision{Resolved: true}
	}

	userID, ok := pe.sessionService.TryInvalidateForRefresh(
		pe.sessionBaseURL,
		identity,
		pe.refreshCooldown,
	)
	if !ok {
		logging.Info(
			"permission refresh skipped",
			"reason", "cooldown",
			"email", identityEmail(identity),
			"upn", identityUPN(identity),
		)

		return AllowDecision{Resolved: true}
	}

	if userID == "" {
		userID = resolved.userID
	}

	refreshedRoles, err := pe.refreshUserRoles(ctx, identity, userID)
	if err != nil {
		logging.Info(
			"permission refresh failed",
			"email", identityEmail(identity),
			"upn", identityUPN(identity),
			"user_id", userID,
			"err", err,
		)

		return AllowDecision{}
	}

	allowed := AllowResolved(identity, refreshedRoles, required)
	rolesChanged := userRolesChanged(resolved.user, refreshedRoles)

	decision := "denied"
	if allowed {
		decision = "allowed"
	}

	logging.Info(
		"permission refresh",
		"decision", decision,
		"roles_changed", rolesChanged,
		"email", identityEmail(identity),
		"upn", identityUPN(identity),
		"user_id", userID,
	)

	return AllowDecision{
		Allowed:      allowed,
		Refreshed:    true,
		RolesChanged: rolesChanged,
		Resolved:     true,
	}
}

// ResolveUserContext resolves the identity to PrivX roles once, using the
// session cache when available. Callers that authorize many tools (tools/list)
// should invoke this once and reuse the result with AllowResolved.
func (pe *PermissionEngine) ResolveUserContext(ctx context.Context, identity *oauth.IdentityClaims) (*rolestore.User, error) {
	resolved, err := pe.resolveUserRoles(ctx, identity)
	if err != nil {
		return nil, err
	}

	return resolved.user, nil
}

func userRolesChanged(before, after *rolestore.User) bool {
	return !sameFoldSet(roleNames(before), roleNames(after)) ||
		!sameFoldSet(resolvedPermissions(before), resolvedPermissions(after))
}

func sameFoldSet(left, right []string) bool {
	leftSet := foldSet(left)

	rightSet := foldSet(right)
	if len(leftSet) != len(rightSet) {
		return false
	}

	for key := range leftSet {
		if _, ok := rightSet[key]; !ok {
			return false
		}
	}

	return true
}

func foldSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := utils.TrimLower(value)
		if key == "" {
			continue
		}

		set[key] = struct{}{}
	}

	return set
}

// AllowResolved checks tool requirements against an already-resolved PrivX
// user context. Empty requirements always pass. The "authenticated" scope
// passes for any non-nil identity without consulting PrivX roles.
func AllowResolved(identity *oauth.IdentityClaims, resolvedRoles *rolestore.User, required []string) bool {
	if len(required) == 0 {
		return true
	}

	if identity == nil {
		return false
	}

	if len(required) == 1 && required[0] == registry.PermissionAuthenticated {
		return true
	}

	if resolvedRoles == nil {
		return false
	}

	return hasRequiredPermissionsAt(resolvedRoles, required, time.Now())
}

func requiresPrivXResolution(required []string) bool {
	if len(required) == 0 {
		return false
	}

	if len(required) == 1 && required[0] == registry.PermissionAuthenticated {
		return false
	}

	return true
}

func (pe *PermissionEngine) resolveUserRoles(_ context.Context, identity *oauth.IdentityClaims) (userRoleResolution, error) {
	if identity == nil {
		return userRoleResolution{}, fmt.Errorf("identity is required")
	}

	if pe == nil || pe.userAPI == nil {
		return userRoleResolution{}, fmt.Errorf("permission resolution is unavailable")
	}

	if cached, ok := pe.sessionService.Get(pe.sessionBaseURL, identity); ok {
		return userRoleResolution{
			user:      withUserID(cached.ResolvedRoles, cached.UserID),
			userID:    cached.UserID,
			fromCache: true,
		}, nil
	}

	users, err := pe.userAPI.SearchAllUsers(rolestore.UserSearch{})
	if err != nil {
		return userRoleResolution{}, fmt.Errorf("failed to get users from role store: %w", err)
	}

	currentUser, ok := resolveCurrentUser(identity, users, pe.sourceType)
	if !ok {
		return userRoleResolution{}, fmt.Errorf(
			"current user not found for claims: email=%q upn=%q subject=%q source_type=%q",
			identity.Email,
			identity.UPN,
			identity.Subject,
			pe.sourceType,
		)
	}

	resolvedRoles, err := pe.fetchAndCacheRoles(identity, currentUser.ID)
	if err != nil {
		return userRoleResolution{}, err
	}

	return userRoleResolution{
		user:   resolvedRoles,
		userID: currentUser.ID,
	}, nil
}

// refreshUserRoles reloads roles after a cache-hit deny. When userID is known
// it skips SearchAllUsers; otherwise it falls back to the full search path.
func (pe *PermissionEngine) refreshUserRoles(
	ctx context.Context,
	identity *oauth.IdentityClaims,
	userID string,
) (*rolestore.User, error) {
	if userID != "" {
		return pe.fetchAndCacheRoles(identity, userID)
	}

	resolved, err := pe.resolveUserRoles(ctx, identity)
	if err != nil {
		return nil, err
	}

	return resolved.user, nil
}

func (pe *PermissionEngine) fetchAndCacheRoles(identity *oauth.IdentityClaims, userID string) (*rolestore.User, error) {
	if pe == nil || pe.userAPI == nil {
		return nil, fmt.Errorf("permission resolution is unavailable")
	}

	resolvedRoles, err := pe.userAPI.ResolveUserRoles(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user roles for user_id=%q: %w", userID, err)
	}

	resolvedRoles = withUserID(resolvedRoles, userID)

	connectorUserID := ""
	if cached, ok := pe.sessionService.Get(pe.sessionBaseURL, identity); ok {
		connectorUserID = strings.TrimSpace(cached.ConnectorUserID)
	}

	pe.sessionService.Set(pe.sessionBaseURL, identity, session.CachedUserContext{
		UserID:          userID,
		ResolvedRoles:   resolvedRoles,
		ConnectorUserID: connectorUserID,
	})

	return resolvedRoles, nil
}

// withUserID ensures the resolved user carries its PrivX ID when the role-store
// payload omitted it (common on cache hits where ID is stored separately).
func withUserID(user *rolestore.User, userID string) *rolestore.User {
	if user == nil {
		return nil
	}

	if user.ID == "" && userID != "" {
		user.ID = userID
	}

	return user
}

// ** Permission evaluation **

func hasRequiredPermissions(resolvedRoles *rolestore.User, required []string) bool {
	return hasRequiredPermissionsAt(resolvedRoles, required, time.Now())
}

func hasRequiredPermissionsAt(resolvedRoles *rolestore.User, required []string, at time.Time) bool {
	if len(required) == 0 {
		return true
	}

	// Admin role bypass takes precedence over specific permission checks.
	if hasPrivxAdminRole(resolvedRoles) {
		return true
	}

	permissionSet := buildPermissionSet(resolvedRoles, at)
	missing := missingRequirements(required, permissionSet)

	return len(missing) == 0
}

func resolvedPermissions(user *rolestore.User) []string {
	return resolvedPermissionsAt(user, time.Now())
}

func buildPermissionSet(user *rolestore.User, at time.Time) map[string]struct{} {
	permissions := resolvedPermissionsAt(user, at)

	permissionSet := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		key := utils.TrimLower(permission)
		if key == "" {
			continue
		}

		permissionSet[key] = struct{}{}
		// Manage scopes also satisfy the matching view requirement.
		if view, ok := viewScopeForManage(key); ok {
			permissionSet[view] = struct{}{}
		}
	}

	return permissionSet
}

// viewScopeForManage maps "foo-manage" → "foo-view". Non-manage scopes return
// ok=false.
func viewScopeForManage(scope string) (string, bool) {
	const suffix = "-manage"
	if !strings.HasSuffix(scope, suffix) {
		return "", false
	}

	return strings.TrimSuffix(scope, suffix) + "-view", true
}

func missingRequirements(required []string, permissionSet map[string]struct{}) []string {
	missing := make([]string, 0, len(required))
	for _, requirement := range required {
		key := utils.TrimLower(requirement)
		if key == "" {
			continue
		}

		if _, ok := permissionSet[key]; !ok {
			missing = append(missing, requirement)
		}
	}

	return missing
}

func resolvedPermissionsAt(user *rolestore.User, at time.Time) []string {
	if user == nil {
		return nil
	}

	combined := make([]string, 0, len(user.Permissions))
	combined = append(combined, user.Permissions...)

	for _, role := range user.Roles {
		if !isRoleWindowAllowed(at, role.Name, role.Context) {
			continue
		}

		combined = append(combined, role.Permissions...)
	}

	return combined
}

// ** Role helpers **

func hasPrivxAdminRole(user *rolestore.User) bool {
	if user == nil {
		return false
	}

	for _, role := range user.Roles {
		if utils.EqualFoldTrimmed(role.Name, "privx-admin") {
			return true
		}
	}

	return false
}

// ** Identity resolution **

// resolveCurrentUser finds the single PrivX user that matches the supplied
// identity claims and configured source_type. API-CLIENT sourced users are
// skipped. When multiple users share an identifier across directories, only
// the entry whose source_type matches is selected. Zero matches or multiple
// matches with the same source_type are rejected to prevent identity confusion.
func resolveCurrentUser(identity *oauth.IdentityClaims, users []rolestore.User, sourceType string) (*rolestore.User, bool) {
	if identity == nil || sourceType == "" {
		return nil, false
	}

	claimValues := nonEmptyClaims(identity.Email, identity.UPN, identity.Subject)
	if len(claimValues) == 0 {
		return nil, false
	}

	var (
		matchedUsers     []*rolestore.User
		wrongSourceUsers []*rolestore.User
	)

	for i := range users {
		user := &users[i]
		if utils.EqualFoldTrimmed(user.SourceType, "API-CLIENT") {
			continue
		}

		if !matchesAnyClaim(user, claimValues) {
			continue
		}

		if !utils.EqualFoldTrimmed(user.SourceType, sourceType) {
			wrongSourceUsers = append(wrongSourceUsers, user)
			continue
		}

		matchedUsers = append(matchedUsers, user)
	}

	if len(matchedUsers) == 0 && len(wrongSourceUsers) > 0 {
		logWrongSourceTypeMatches(sourceType, claimValues, wrongSourceUsers)
	}

	if len(matchedUsers) != 1 {
		return nil, false
	}

	return matchedUsers[0], true
}

// logWrongSourceTypeMatches records identifier matches that were rejected
// because their PrivX source_type does not match the configured value.
func logWrongSourceTypeMatches(wantedSourceType string, claims []string, users []*rolestore.User) {
	parts := make([]string, 0, len(users))
	for _, user := range users {
		if user == nil {
			continue
		}

		parts = append(parts, fmt.Sprintf(
			"principal=%q id=%q source_type=%q",
			user.Principal,
			user.ID,
			user.SourceType,
		))
	}

	logging.Debug(
		"identity matched users with non-matching source_type",
		"wanted_source_type", wantedSourceType,
		"claims", claims,
		"candidates", strings.Join(parts, "; "),
	)
}

// matchesAnyClaim reports whether the user matches any of the supplied claim
// values. Email-shaped claims are matched against the user's email and
// Windows account; other claims are matched against the user's principal.
func matchesAnyClaim(user *rolestore.User, claims []string) bool {
	if user == nil {
		return false
	}

	for _, claim := range claims {
		if utils.IsLikelyAddress(claim) {
			if utils.EqualFoldTrimmed(user.Email, claim) || utils.EqualFoldTrimmed(user.WindowsAccount, claim) {
				return true
			}

			continue
		}

		if utils.EqualFoldTrimmed(user.Principal, claim) {
			return true
		}
	}

	return false
}

// nonEmptyClaims returns the input values with empty strings removed.
func nonEmptyClaims(values ...string) []string {
	claims := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			claims = append(claims, value)
		}
	}

	return claims
}

// ** Role time-window gating **

// isRoleWindowAllowed reports whether a role's contextual limits permit
// activation at the given instant. A disabled context always passes; an
// enabled context must satisfy both the weekday validity set and, when a
// timezone is configured, the daily time window. Evaluation errors deny
// the role (fail-closed).
func isRoleWindowAllowed(at time.Time, roleName string, limit rolestore.ContextualLimit) bool {
	if !limit.Enabled {
		logging.Debug("role window check skipped", "role", roleName, "context_enabled", false)
		return true
	}

	if len(limit.Validity) > 0 {
		allowedToday, err := dateutils.IsWeekdayInLocation(at, limit.TimeZone, limit.Validity)
		if err != nil {
			logging.Error("failed to evaluate role validity days", "role", roleName, "err", err)
			logRoleWindowResult(roleName, limit, false, []string{"validity_evaluation_error"}, "")

			return false
		}

		if !allowedToday {
			logRoleWindowResult(roleName, limit, false, []string{"validity_day_mismatch"}, "")
			return false
		}
	}

	allowed, passReason, err := timeRangeAllows(at, limit.TimeZone, limit.StartTime, limit.EndTime)
	if err != nil {
		logging.Error("failed to evaluate role time range", "role", roleName, "err", err)
		logRoleWindowResult(roleName, limit, false, []string{"time_range_evaluation_error"}, "")

		return false
	}

	if !allowed {
		logRoleWindowResult(roleName, limit, false, []string{"time_range_mismatch"}, "")
		return false
	}

	logRoleWindowResult(roleName, limit, true, nil, passReason)

	return true
}

// timeRangeAllows reports whether the daily clock window allows activation.
// An empty timezone skips range enforcement. A midnight-to-midnight window
// is a no-op. On evaluation error, allowed is false so callers fail closed.
func timeRangeAllows(at time.Time, timezone, startHHMM, endHHMM string) (allowed bool, passReason string, err error) {
	if timezone == "" {
		return true, "no_timezone_range_enforcement", nil
	}

	if dateutils.IsMidnightNoopWindow(startHHMM, endHHMM) {
		return true, "midnight_noop_window", nil
	}

	ok, err := dateutils.IsWithinRangeOfTimeZone(at, timezone, startHHMM, endHHMM)
	if err != nil {
		return false, "", err
	}

	return ok, "", nil
}

func logRoleWindowResult(
	roleName string,
	limit rolestore.ContextualLimit,
	matched bool,
	denyReasons []string,
	passReason string,
) {
	msg := "role window check passed"
	if !matched {
		msg = "role window check denied"
	}

	attrs := []any{
		"role", roleName,
		"context_enabled", true,
		"matched", matched,
	}
	if !matched {
		attrs = append(attrs, "reasons", denyReasons)
	} else if passReason != "" {
		attrs = append(attrs, "reason", passReason)
	}

	attrs = append(
		attrs,
		"timezone", limit.TimeZone,
		"validity", limit.Validity,
		"start", limit.StartTime,
		"end", limit.EndTime,
	)

	logging.Debug(msg, attrs...)
}
