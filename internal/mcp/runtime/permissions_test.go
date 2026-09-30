package runtime

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
)

type stubPermissionUserAPI struct {
	searchUsersResult []rolestore.User
	searchUsersErr    error
	resolveByID       map[string]*rolestore.User
	resolveErr        error
	searchCalls       int
	resolveCalls      int
}

func (s *stubPermissionUserAPI) SearchAllUsers(rolestore.UserSearch) ([]rolestore.User, error) {
	s.searchCalls++
	if s.searchUsersErr != nil {
		return nil, s.searchUsersErr
	}
	return s.searchUsersResult, nil
}

func (s *stubPermissionUserAPI) ResolveUserRoles(userID string) (*rolestore.User, error) {
	s.resolveCalls++
	if s.resolveErr != nil {
		return nil, s.resolveErr
	}
	user, ok := s.resolveByID[userID]
	if !ok {
		return nil, fmt.Errorf("unknown user id %q", userID)
	}
	return user, nil
}

func isAllowed(t *testing.T, pe *PermissionEngine, identity *oauth.IdentityClaims, required []string) bool {
	t.Helper()

	return pe.IsAllowed(context.Background(), identity, required).Allowed
}

func TestIsAllowed_AllowsToolWithoutRequirements(t *testing.T) {
	pe := NewPermissionEngine()
	if !isAllowed(t, pe, nil, nil) {
		t.Fatal("expected tool with no requirements to be allowed")
	}
}

func TestIsAllowed_DeniesWhenIdentityMissing(t *testing.T) {
	pe := NewPermissionEngine()

	if isAllowed(t, pe, nil, []string{"hosts-view"}) {
		t.Fatal("expected access denied when identity is missing")
	}
}

func TestIsAllowed_DeniesWhenIdentityPresentAndPermissionResolutionUnavailable(t *testing.T) {
	pe := NewPermissionEngine()
	if isAllowed(t, pe, &oauth.IdentityClaims{Email: "alice@example.com"}, []string{"hosts-view"}) {
		t.Fatal("expected deny behavior when permission resolution is unavailable")
	}
}

func TestIsAllowed_UsesCacheHitWithoutPrivXLookup(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}
	cache.Set("https://privx.example.com", identity, session.CachedUserContext{
		UserID: "user-1",
		ResolvedRoles: &rolestore.User{
			Permissions: []string{"hosts-view"},
		},
	})

	api := &stubPermissionUserAPI{}
	pe := &PermissionEngine{
		userAPI:        api,
		sessionService: cache,
		sessionBaseURL: "https://privx.example.com",
	}

	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected allow from cached permissions")
	}
	if api.searchCalls != 0 || api.resolveCalls != 0 {
		t.Fatalf("expected no PrivX API calls on cache hit, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestResolveUserContext_PopulatesUserIDOnMissAndCacheHit(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}

	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			// Resolve payload intentionally omits ID; withUserID should fill it.
			"user-1": {Permissions: []string{"hosts-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:        api,
		sessionService: cache,
		sessionBaseURL: "https://privx.example.com",
		sourceType:     "AD",
	}

	miss, err := pe.ResolveUserContext(context.Background(), identity)
	if err != nil {
		t.Fatalf("resolve on miss: %v", err)
	}
	if miss == nil || miss.ID != "user-1" {
		t.Fatalf("expected user ID user-1 on miss, got %#v", miss)
	}

	hit, err := pe.ResolveUserContext(context.Background(), identity)
	if err != nil {
		t.Fatalf("resolve on cache hit: %v", err)
	}
	if hit == nil || hit.ID != "user-1" {
		t.Fatalf("expected user ID user-1 on cache hit, got %#v", hit)
	}
	if api.searchCalls != 1 || api.resolveCalls != 1 {
		t.Fatalf("expected one PrivX lookup, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_CachesMissForSubsequentHit(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}

	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"hosts-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:        api,
		sessionService: cache,
		sessionBaseURL: "https://privx.example.com",
		sourceType:     "AD",
	}

	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected first permission check to allow")
	}
	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected second permission check to allow")
	}
	if api.searchCalls != 1 || api.resolveCalls != 1 {
		t.Fatalf("expected one PrivX lookup before cache hit, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_CacheMissAfterExpiry(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(5*time.Second, func() time.Time { return now })
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}

	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"hosts-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:        api,
		sessionService: cache,
		sessionBaseURL: "https://privx.example.com",
		sourceType:     "AD",
	}

	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected first permission check to allow")
	}
	now = now.Add(6 * time.Second)
	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected permission check after ttl expiry to still allow")
	}
	if api.searchCalls != 2 || api.resolveCalls != 2 {
		t.Fatalf("expected PrivX lookups to rerun after ttl expiry, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_BypassesCacheWhenDisabled(t *testing.T) {
	cache := session.NewService(0)
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}

	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"hosts-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:        api,
		sessionService: cache,
		sessionBaseURL: "https://privx.example.com",
		sourceType:     "AD",
	}

	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected first permission check to allow")
	}
	if !isAllowed(t, pe, identity, []string{"hosts-view"}) {
		t.Fatal("expected second permission check to allow")
	}
	if api.searchCalls != 2 || api.resolveCalls != 2 {
		t.Fatalf("expected disabled cache to bypass storage, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_CacheDenyRefreshGrantsWithoutUserSearch(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := refreshTestIdentity()
	cache.Set("https://privx.example.com", identity, session.CachedUserContext{
		UserID: "user-1",
		ResolvedRoles: &rolestore.User{
			Permissions: []string{"users-view"},
		},
	})

	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"hosts-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  cache,
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: time.Minute,
	}

	got := pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if !got.Allowed {
		t.Fatal("expected refresh to allow after PrivX granted the scope")
	}
	if !got.Refreshed {
		t.Fatal("expected on-deny refresh to complete")
	}
	if !got.RolesChanged {
		t.Fatal("expected roles/permissions to differ from the cache")
	}
	if api.searchCalls != 0 {
		t.Fatalf("expected no SearchAllUsers when UserID is known, got %d", api.searchCalls)
	}
	if api.resolveCalls != 1 {
		t.Fatalf("expected one ResolveUserRoles on refresh, got %d", api.resolveCalls)
	}
}

func TestIsAllowed_CacheDenyRefreshStillDeniesAndCooldownSkips(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := refreshTestIdentity()
	cache.Set("https://privx.example.com", identity, session.CachedUserContext{
		UserID: "user-1",
		ResolvedRoles: &rolestore.User{
			Permissions: []string{"users-view"},
		},
	})

	api := &stubPermissionUserAPI{
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"users-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  cache,
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: time.Minute,
	}

	got := pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if got.Allowed {
		t.Fatal("expected deny after refresh when PrivX still lacks the scope")
	}
	if !got.Refreshed {
		t.Fatal("expected first deny to complete an on-deny refresh")
	}
	if got.RolesChanged {
		t.Fatal("expected unchanged roles/permissions not to be flagged as a role change")
	}
	if api.resolveCalls != 1 {
		t.Fatalf("expected one ResolveUserRoles on refresh, got %d", api.resolveCalls)
	}

	got = pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if got.Allowed {
		t.Fatal("expected second deny inside cooldown")
	}
	if got.Refreshed {
		t.Fatal("expected cooldown to skip a second refresh")
	}
	if got.RolesChanged {
		t.Fatal("expected cooldown skip not to report a role change")
	}
	if api.searchCalls != 0 || api.resolveCalls != 1 {
		t.Fatalf("expected zero further API calls inside cooldown, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_DenyOnCacheMissDoesNotRefreshAgain(t *testing.T) {
	cache := session.NewService(30 * time.Second)
	identity := refreshTestIdentity()
	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"users-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  cache,
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: time.Minute,
	}

	got := pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if got.Allowed {
		t.Fatal("expected deny on cache miss when PrivX lacks the scope")
	}
	if got.Refreshed {
		t.Fatal("expected no on-deny refresh after a fresh PrivX fetch")
	}
	if got.RolesChanged {
		t.Fatal("expected no role-change flag on a cache-miss deny")
	}
	if !got.Resolved {
		t.Fatal("expected PrivX context to be resolved on a cache-miss deny")
	}
	if api.searchCalls != 1 || api.resolveCalls != 1 {
		t.Fatalf("expected one PrivX round-trip, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_RefreshCooldownZeroSkipsRefresh(t *testing.T) {
	cache := session.NewService(30 * time.Second)
	identity := refreshTestIdentity()
	cache.Set("https://privx.example.com", identity, session.CachedUserContext{
		UserID: "user-1",
		ResolvedRoles: &rolestore.User{
			Permissions: []string{"users-view"},
		},
	})

	api := &stubPermissionUserAPI{
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"hosts-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  cache,
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: 0,
	}

	got := pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if got.Allowed {
		t.Fatal("expected cached deny to stand when refresh cooldown is 0")
	}
	if got.Refreshed {
		t.Fatal("expected no refresh when cooldown is 0")
	}
	if api.searchCalls != 0 || api.resolveCalls != 0 {
		t.Fatalf("expected no PrivX calls when cooldown is 0, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_DisabledCacheDoesNotExtraRefresh(t *testing.T) {
	cache := session.NewService(0)
	identity := refreshTestIdentity()
	api := &stubPermissionUserAPI{
		searchUsersResult: []rolestore.User{
			{
				ID:         "user-1",
				Email:      "alice@example.com",
				Principal:  "alice",
				SourceType: "AD",
			},
		},
		resolveByID: map[string]*rolestore.User{
			"user-1": {Permissions: []string{"users-view"}},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  cache,
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: time.Minute,
	}

	got := pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if got.Allowed {
		t.Fatal("expected deny when cache is disabled and PrivX lacks the scope")
	}
	if got.Refreshed {
		t.Fatal("expected no extra refresh when caching is disabled")
	}
	if api.searchCalls != 1 || api.resolveCalls != 1 {
		t.Fatalf("expected one PrivX round-trip, got search=%d resolve=%d", api.searchCalls, api.resolveCalls)
	}
}

func TestIsAllowed_CacheDenyRefreshRolesRemoved(t *testing.T) {
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
	identity := refreshTestIdentity()
	cache.Set("https://privx.example.com", identity, session.CachedUserContext{
		UserID: "user-1",
		ResolvedRoles: &rolestore.User{
			Roles: []rolestore.Role{
				{Name: "privx-user"},
				{Name: "roles-manager"},
			},
			Permissions: []string{"users-view"},
		},
	})

	api := &stubPermissionUserAPI{
		resolveByID: map[string]*rolestore.User{
			"user-1": {
				Roles: []rolestore.Role{
					{Name: "privx-user"},
				},
				Permissions: []string{"users-view"},
			},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  cache,
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: time.Minute,
	}

	got := pe.IsAllowed(context.Background(), identity, []string{"hosts-view"})
	if got.Allowed {
		t.Fatal("expected deny after extra role was removed")
	}
	if !got.Refreshed {
		t.Fatal("expected on-deny refresh to complete")
	}
	if !got.RolesChanged {
		t.Fatal("expected role removal to be flagged as a role change")
	}
}

func refreshTestIdentity() *oauth.IdentityClaims {
	return &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}
}

func TestFindCurrentUser_MatchesEmailToEmailOrWindowsAccount(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:      "api-client-user",
			Email:          "ignored@example.com",
			WindowsAccount: "ignored@example.com",
			SourceType:     "API-CLIENT",
			Roles:          []rolestore.Role{{ID: "r-ignored"}},
		},
		{
			Principal:      "alice",
			Email:          "alice@example.com",
			WindowsAccount: "alice@corp.local",
			SourceType:     "AD",
			Roles:          nil,
		},
	}

	if user, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@example.com"}, users, "AD"); !ok || user.Principal != "alice" {
		t.Fatalf("expected email to match user.email, got ok=%v principal=%q", ok, principalOrEmpty(user))
	}

	if user, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@corp.local"}, users, "AD"); !ok || user.Principal != "alice" {
		t.Fatalf("expected email to match user.windows_account, got ok=%v principal=%q", ok, principalOrEmpty(user))
	}
}

func TestFindCurrentUser_MatchesUsernameToPrincipal(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:  "demouser",
			Email:      "demo@example.com",
			SourceType: "LOCAL",
			Roles:      nil,
		},
	}

	user, ok := resolveCurrentUser(&oauth.IdentityClaims{UPN: "demouser"}, users, "LOCAL")
	if !ok {
		t.Fatal("expected username identity to match principal")
	}
	if user.Principal != "demouser" {
		t.Fatalf("expected principal demouser, got %q", user.Principal)
	}
}

func TestFindCurrentUser_SkipsAPIClients(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:  "target",
			Email:      "target@example.com",
			SourceType: "API-CLIENT",
			Roles:      []rolestore.Role{{ID: "r1"}},
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "target@example.com"}, users, "API-CLIENT"); ok {
		t.Fatal("expected API-CLIENT source users to be ignored")
	}
}

func TestFindCurrentUser_PicksMatchingSourceTypeAmongDuplicates(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:      "alice-local",
			Email:          "alice@example.com",
			WindowsAccount: "alice@corp.local",
			SourceType:     "LOCAL",
		},
		{
			Principal:      "alice-ad",
			Email:          "alice@example.com",
			WindowsAccount: "alice2@corp.local",
			SourceType:     "AD",
		},
	}

	user, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@example.com"}, users, "AD")
	if !ok || user.Principal != "alice-ad" {
		t.Fatalf("expected AD source_type match, got ok=%v principal=%q", ok, principalOrEmpty(user))
	}
}

func TestFindCurrentUser_DeniesWhenMultipleUsersShareSourceType(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:  "alice-ad-1",
			Email:      "alice@example.com",
			SourceType: "AD",
		},
		{
			Principal:  "alice-ad-2",
			Email:      "alice@example.com",
			SourceType: "AD",
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@example.com"}, users, "AD"); ok {
		t.Fatal("expected multiple users with same source_type to be denied")
	}
}

func TestFindCurrentUser_DeniesWhenNoMatchingSourceType(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:  "alice-local",
			Email:      "alice@example.com",
			SourceType: "LOCAL",
		},
		{
			Principal:  "alice-graph",
			Email:      "alice@example.com",
			SourceType: "MICROSOFTGRAPH",
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@example.com"}, users, "AD"); ok {
		t.Fatal("expected no matching source_type to be denied")
	}
}

func TestFindCurrentUser_DeniesWhenPrincipalMatchesMultipleUsersWithSameSourceType(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:  "demouser",
			Email:      "demo1@example.com",
			SourceType: "AD",
		},
		{
			Principal:  "demouser",
			Email:      "demo2@example.com",
			SourceType: "AD",
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{UPN: "demouser"}, users, "AD"); ok {
		t.Fatal("expected ambiguous principal match with same source_type to be denied")
	}
}

func TestFindCurrentUser_DeniesWhenClaimsMatchNoUsers(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:      "alice",
			Email:          "alice@example.com",
			WindowsAccount: "alice@corp.local",
			SourceType:     "AD",
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "bob@example.com", UPN: "bob"}, users, "AD"); ok {
		t.Fatal("expected unmatched claims to be denied")
	}
}

func TestFindCurrentUser_DeniesWhenClaimsMatchDifferentUsers(t *testing.T) {
	users := []rolestore.User{
		{
			ID:             "u-1",
			Principal:      "alice",
			Email:          "alice@example.com",
			WindowsAccount: "alice@corp.local",
			SourceType:     "AD",
		},
		{
			ID:         "u-2",
			Principal:  "bob",
			Email:      "bob@example.com",
			SourceType: "AD",
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@example.com", UPN: "bob"}, users, "AD"); ok {
		t.Fatal("expected claims resolving to multiple users to be denied")
	}
}

func TestFindCurrentUser_DeniesWhenSourceTypeEmpty(t *testing.T) {
	users := []rolestore.User{
		{
			Principal:  "alice",
			Email:      "alice@example.com",
			SourceType: "AD",
		},
	}

	if _, ok := resolveCurrentUser(&oauth.IdentityClaims{Email: "alice@example.com"}, users, ""); ok {
		t.Fatal("expected empty source_type to be denied")
	}
}

func principalOrEmpty(user *rolestore.User) string {
	if user == nil {
		return ""
	}
	return user.Principal
}

func TestHasRequiredPermissions_AllPresent(t *testing.T) {
	resolvedRoles := &rolestore.User{
		Permissions: []string{"hosts-view", "sessions-view", "  Reports-Read "},
	}
	required := []string{"hosts-view", "reports-read"}

	if !hasRequiredPermissions(resolvedRoles, required) {
		t.Fatal("expected requirements to match resolved permissions")
	}
}

func TestHasRequiredPermissions_MissingRequired(t *testing.T) {
	resolvedRoles := &rolestore.User{
		Permissions: []string{"hosts-view"},
	}
	required := []string{"hosts-view", "reports-read"}

	if hasRequiredPermissions(resolvedRoles, required) {
		t.Fatal("expected missing requirement to deny access")
	}
}

func TestHasRequiredPermissions_ManageSatisfiesView(t *testing.T) {
	resolvedRoles := &rolestore.User{
		Permissions: []string{"hosts-manage"},
	}
	if !hasRequiredPermissions(resolvedRoles, []string{"hosts-view"}) {
		t.Fatal("expected hosts-manage to satisfy hosts-view")
	}
	if !hasRequiredPermissions(resolvedRoles, []string{"hosts-manage"}) {
		t.Fatal("expected hosts-manage to satisfy hosts-manage")
	}
}

func TestResolvedPermissions_CollectsFromUserAndRoles(t *testing.T) {
	user := &rolestore.User{
		Permissions: []string{"users-view"},
		Roles: []rolestore.Role{
			{Permissions: []string{"hosts-view"}},
			{Permissions: []string{"reports-read", "hosts-view"}},
		},
	}

	permissions := resolvedPermissions(user)
	if !hasRequiredPermissions(user, []string{"users-view", "hosts-view", "reports-read"}) {
		t.Fatalf("expected combined permissions from user and roles, got %v", permissions)
	}
}

func TestHasPrivxAdminRole(t *testing.T) {
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{Name: "other-role"},
			{Name: " PrivX-Admin "},
		},
	}

	if !hasPrivxAdminRole(user) {
		t.Fatal("expected privx-admin role to grant full access bypass")
	}
}

func TestHasPrivxAdminRole_False(t *testing.T) {
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{Name: "privx-user"},
		},
	}

	if hasPrivxAdminRole(user) {
		t.Fatal("expected non-admin roles to not trigger bypass")
	}
}

func TestHasRequiredPermissions_AdminBypass(t *testing.T) {
	resolvedRoles := &rolestore.User{
		Roles: []rolestore.Role{
			{Name: "privx-admin"},
		},
	}

	if !hasRequiredPermissions(resolvedRoles, []string{"this-permission-does-not-exist"}) {
		t.Fatal("expected privx-admin role to bypass required permission checks")
	}
}

func TestResolvedPermissionsAt_ContextEnabledValidityMismatch(t *testing.T) {
	at := testTimeUTC(t, "2026-07-07T09:30:00Z") // Tuesday
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				Permissions: []string{"hosts-view"},
				Context: rolestore.ContextualLimit{
					Enabled:  true,
					Validity: []string{"MON", "WED"},
				},
			},
		},
	}

	permissions := resolvedPermissionsAt(user, at)
	if len(permissions) != 0 {
		t.Fatalf("expected no permissions from invalid weekday, got %v", permissions)
	}
}

func TestResolvedPermissionsAt_ContextEnabledValidityMatch(t *testing.T) {
	at := testTimeUTC(t, "2026-07-06T09:30:00Z") // Monday
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				Permissions: []string{"hosts-view"},
				Context: rolestore.ContextualLimit{
					Enabled:  true,
					Validity: []string{"MON", "WED"},
				},
			},
		},
	}

	permissions := resolvedPermissionsAt(user, at)
	if !hasRequiredPermissions(&rolestore.User{Permissions: permissions}, []string{"hosts-view"}) {
		t.Fatalf("expected weekday-matching context to allow permission, got %v", permissions)
	}
}

func TestResolvedPermissionsAt_ContextEnabledTimezoneRangeMatch(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T06:30:00Z") // 09:30 Europe/Helsinki
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				Permissions: []string{"hosts-view"},
				Context: rolestore.ContextualLimit{
					Enabled:   true,
					TimeZone:  "Europe/Helsinki",
					StartTime: "09:00",
					EndTime:   "10:00",
				},
			},
		},
	}

	permissions := resolvedPermissionsAt(user, at)
	if !hasRequiredPermissions(&rolestore.User{Permissions: permissions}, []string{"hosts-view"}) {
		t.Fatalf("expected in-range context to allow permission, got %v", permissions)
	}
}

func TestResolvedPermissionsAt_ContextEnabledTimezoneRangeNoMatch(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T09:30:00Z") // 12:30 Europe/Helsinki
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				Permissions: []string{"hosts-view"},
				Context: rolestore.ContextualLimit{
					Enabled:   true,
					TimeZone:  "Europe/Helsinki",
					StartTime: "09:00",
					EndTime:   "10:00",
				},
			},
		},
	}

	permissions := resolvedPermissionsAt(user, at)
	if len(permissions) != 0 {
		t.Fatalf("expected no permissions for out-of-range context, got %v", permissions)
	}
}

func TestResolvedPermissionsAt_ContextEnabledTimezoneEmptySkipsTimeRange(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T22:30:00Z")
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				Permissions: []string{"hosts-view"},
				Context: rolestore.ContextualLimit{
					Enabled:   true,
					TimeZone:  "",
					StartTime: "09:00",
					EndTime:   "10:00",
				},
			},
		},
	}

	permissions := resolvedPermissionsAt(user, at)
	if !hasRequiredPermissions(&rolestore.User{Permissions: permissions}, []string{"hosts-view"}) {
		t.Fatalf("expected empty timezone to skip time window checks, got %v", permissions)
	}
}

func TestResolvedPermissionsAt_ContextEnabledTimezoneMidnightNoopSkipsTimeRange(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T22:30:00Z")
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				Permissions: []string{"hosts-view"},
				Context: rolestore.ContextualLimit{
					Enabled:   true,
					TimeZone:  "Europe/Helsinki",
					StartTime: "00:00",
					EndTime:   "00:00",
				},
			},
		},
	}

	permissions := resolvedPermissionsAt(user, at)
	if !hasRequiredPermissions(&rolestore.User{Permissions: permissions}, []string{"hosts-view"}) {
		t.Fatalf("expected 00:00-00:00 to skip time window checks, got %v", permissions)
	}
}

func TestResolvedPermissionsAt_ContextEnabledFailClosed(t *testing.T) {
	at := testTimeUTC(t, "2026-07-06T09:30:00Z") // Monday

	tests := []struct {
		name  string
		limit rolestore.ContextualLimit
	}{
		{
			name: "invalid weekday token",
			limit: rolestore.ContextualLimit{
				Enabled:  true,
				Validity: []string{"NOTADAY"},
			},
		},
		{
			name: "invalid timezone for weekday",
			limit: rolestore.ContextualLimit{
				Enabled:  true,
				TimeZone: "Invalid/Timezone",
				Validity: []string{"MON"},
			},
		},
		{
			name: "invalid timezone for time range",
			limit: rolestore.ContextualLimit{
				Enabled:   true,
				TimeZone:  "Invalid/Timezone",
				StartTime: "09:00",
				EndTime:   "17:00",
			},
		},
		{
			name: "invalid start clock",
			limit: rolestore.ContextualLimit{
				Enabled:   true,
				TimeZone:  "UTC",
				StartTime: "25:00",
				EndTime:   "17:00",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user := &rolestore.User{
				Roles: []rolestore.Role{
					{Permissions: []string{"hosts-view"}, Context: tc.limit},
				},
			}

			permissions := resolvedPermissionsAt(user, at)
			if len(permissions) != 0 {
				t.Fatalf("expected fail-closed denial, got %v", permissions)
			}
		})
	}
}

func TestTimeRangeAllows(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T06:30:00Z") // 09:30 Europe/Helsinki

	tests := []struct {
		name       string
		timezone   string
		start      string
		end        string
		wantOK     bool
		wantReason string
		wantErr    bool
	}{
		{
			name:       "empty timezone skips range",
			start:      "09:00",
			end:        "10:00",
			wantOK:     true,
			wantReason: "no_timezone_range_enforcement",
		},
		{
			name:       "midnight noop",
			timezone:   "Europe/Helsinki",
			start:      "00:00",
			end:        "00:00",
			wantOK:     true,
			wantReason: "midnight_noop_window",
		},
		{
			name:     "in range",
			timezone: "Europe/Helsinki",
			start:    "09:00",
			end:      "10:00",
			wantOK:   true,
		},
		{
			name:     "out of range",
			timezone: "Europe/Helsinki",
			start:    "10:00",
			end:      "11:00",
		},
		{
			name:     "invalid timezone",
			timezone: "Invalid/Timezone",
			start:    "09:00",
			end:      "17:00",
			wantErr:  true,
		},
		{
			name:     "invalid start",
			timezone: "UTC",
			start:    "25:00",
			end:      "17:00",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason, err := timeRangeAllows(at, tc.timezone, tc.start, tc.end)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected evaluation error")
				}
				if ok {
					t.Fatal("evaluation error must fail closed")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("allowed = %v, want %v", ok, tc.wantOK)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func testTimeUTC(t *testing.T, value string) time.Time {
	t.Helper()

	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse test time: %v", err)
	}
	return parsed
}
