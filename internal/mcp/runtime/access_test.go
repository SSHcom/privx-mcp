package runtime

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/service/session"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

type stubClaimsSource struct {
	claims *oauth.IdentityClaims
}

func (s stubClaimsSource) ToolCallClaims(context.Context) *oauth.IdentityClaims {
	return s.claims
}

func (s stubClaimsSource) ListClaims(context.Context) *oauth.IdentityClaims {
	return s.claims
}

func (s stubClaimsSource) MissingClaimsMessage() string {
	return "missing claims"
}

type stubAuth struct {
	authCtx *auth.AuthContext
	err     error
	calls   *int
}

func (s stubAuth) Authenticate(context.Context, *oauth.IdentityClaims) (*auth.AuthContext, error) {
	if s.calls != nil {
		*s.calls++
	}

	return s.authCtx, s.err
}

func newCoreForPermissionsTest(t *testing.T, identity *oauth.IdentityClaims) *Core {
	t.Helper()

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		Description:         "test tool",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema: map[string]any{
			"type": "object",
		},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{
				Content: []registry.ContentBlock{{Type: "text", Text: "ok"}},
			}, nil
		},
	})

	return NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		NewPermissionEngine(),
		stubClaimsSource{claims: identity},
	)
}

func testCallRequest(name string) *mcp.CallToolRequest {
	return &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: name},
	}
}

func okCallResult() *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
	}
}

func TestAuthMiddleware_DeniesWhenPermissionResolutionUnavailable(t *testing.T) {
	identity := &oauth.IdentityClaims{Issuer: "https://issuer.example.com", Subject: "user", Email: "alice@example.com"}
	core := newCoreForPermissionsTest(t, identity)

	request := testCallRequest("host-list")

	nextCalled := false
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalled = true
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if nextCalled {
		t.Fatal("expected middleware to block handler when permission resolution is unavailable")
	}
}

func TestAuthMiddleware_DeniesWhenIdentityMissing(t *testing.T) {
	core := newCoreForPermissionsTest(t, nil)

	request := testCallRequest("host-list")

	nextCalled := false
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalled = true
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if nextCalled {
		t.Fatal("expected middleware to block handler when identity is missing")
	}
}

func TestAuthMiddleware_DeniesWhenToolMissingFromRegistry(t *testing.T) {
	identity := &oauth.IdentityClaims{Issuer: "https://issuer.example.com", Subject: "user", Email: "alice@example.com"}
	core := newCoreForPermissionsTest(t, identity)

	request := testCallRequest("unknown-tool")

	nextCalled := false
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalled = true
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if nextCalled {
		t.Fatal("expected middleware to fail closed for unknown tools")
	}
}

func TestAuthMiddleware_RateLimitExceeded(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user",
		Email:   "alice@example.com",
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "echo",
		Description:         "test tool",
		RequiredPermissions: []string{registry.PermissionAuthenticated},
		InputSchema: map[string]any{
			"type": "object",
		},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{
				Content: []registry.ContentBlock{{Type: "text", Text: "ok"}},
			}, nil
		},
	})

	limiter := session.NewRateLimiter(60, 1, 0)
	authCalls := 0
	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}, calls: &authCalls},
		reg,
		NewPermissionEngine(),
		stubClaimsSource{claims: identity},
		WithRateLimiter(limiter, "https://privx.example.com"),
	)

	request := testCallRequest("echo")

	nextCalls := 0
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalls++
		return okCallResult(), nil
	})

	first, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error on first call, got: %v", err)
	}
	if first == nil || first.IsError {
		t.Fatalf("expected first call to succeed, got %#v", first)
	}
	if nextCalls != 1 {
		t.Fatalf("expected next called once, got %d", nextCalls)
	}
	if authCalls != 1 {
		t.Fatalf("expected PrivX login on the allowed call, got %d", authCalls)
	}

	second, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error on second call, got: %v", err)
	}
	if second == nil || !second.IsError {
		t.Fatalf("expected second call to be rate limited, got %#v", second)
	}
	if nextCalls != 1 {
		t.Fatalf("expected next not called after rate limit, got %d", nextCalls)
	}
	if authCalls != 1 {
		t.Fatalf("expected no PrivX login after rate limit, got %d", authCalls)
	}
	text, ok := second.Content[0].(*mcp.TextContent)
	if !ok || text.Text != rateLimitExceededMessage {
		t.Fatalf("unexpected rate limit message: %#v", second.Content)
	}
}

func TestAuthMiddleware_RejectsChangedIssuerSubject(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user-1",
		Email:   "alice@example.com",
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "echo",
		RequiredPermissions: []string{registry.PermissionAuthenticated},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	pe := NewPermissionEngine()
	pe.sessionService = session.NewService(time.Minute)
	pe.sessionBaseURL = "https://privx.example.com"

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return okCallResult(), nil
	})

	first, err := handler(context.Background(), testCallRequest("echo"))
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if first == nil || first.IsError {
		t.Fatalf("expected first call to succeed, got %#v", first)
	}

	identity.Subject = "user-2"
	second, err := handler(context.Background(), testCallRequest("echo"))
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if second == nil || !second.IsError {
		t.Fatalf("expected changed subject to be rejected, got %#v", second)
	}
	text, ok := second.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "authentication failed: "+session.ErrIssuerSubjectChanged.Error() {
		t.Fatalf("unexpected binding message: %#v", second.Content)
	}
}

func TestAuthMiddleware_PopulatesActiveRolesOnAuthContext(t *testing.T) {
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
			"user-1": {
				Permissions: []string{"hosts-view"},
				Roles: []rolestore.Role{
					{ID: "role-approver", Name: "approver"},
					{ID: "role-viewer", Name: "viewer"},
				},
			},
		},
	}
	pe := &PermissionEngine{
		userAPI:    api,
		sourceType: "AD",
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("host-list")

	var got *auth.AuthContext
	handler := core.authMiddleware(func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		got = auth.FromContext(ctx)
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("expected successful call, got %#v", result)
	}
	if got == nil {
		t.Fatal("expected AuthContext in handler")
	}
	if !got.HasRole("approver") || !got.HasRole("viewer") {
		t.Fatalf("expected active roles on AuthContext, got %v", got.Roles)
	}
	if !got.HasRole("", "role-approver") || !got.HasRole("viewer", "role-viewer") {
		t.Fatalf("expected role IDs on AuthContext, got %v", got.Roles)
	}
	if got.UserID != "user-1" {
		t.Fatalf("expected UserID user-1 on AuthContext, got %q", got.UserID)
	}
}

func TestAuthMiddleware_AuthenticatedToolAllowsWithEmptyRolesWhenResolveFails(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "user",
		Email:   "alice@example.com",
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "echo",
		RequiredPermissions: []string{registry.PermissionAuthenticated},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		NewPermissionEngine(), // no userAPI → resolve fails
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("echo")

	var got *auth.AuthContext
	handler := core.authMiddleware(func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		got = auth.FromContext(ctx)
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("expected authenticated tool to be allowed, got %#v", result)
	}
	if got == nil {
		t.Fatal("expected AuthContext in handler")
	}
	if len(got.Roles) != 0 {
		t.Fatalf("expected empty Roles when resolve fails, got %v", got.Roles)
	}
	if got.UserID != "" {
		t.Fatalf("expected empty UserID when resolve fails, got %q", got.UserID)
	}
}

func TestAuthMiddleware_DeniesWhenConnectorUserDiffersFromResolvedUser(t *testing.T) {
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
			"user-1": {
				Permissions: []string{"hosts-view"},
			},
		},
	}
	pe := &PermissionEngine{
		userAPI:    api,
		sourceType: "AD",
	}

	fake := testconn.New(t)
	fake.Handle("GET", "/role-store/api/v1/users/current", func(any) (any, error) {
		return map[string]any{
			"id":          "user-2",
			"principal":   "mallory",
			"source_type": "AD",
		}, nil
	})

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice", Connector: fake}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("host-list")
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("handler should not run on identity mismatch")
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected identity mismatch to deny, got %#v", result)
	}
}

func TestAuthMiddleware_UsesCachedConnectorUserIDWhenResolvedUserMatches(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}
	cache := session.NewService(30 * time.Second)
	cache.Set("https://privx.example.com", identity, session.CachedUserContext{
		UserID:          "user-1",
		ConnectorUserID: "user-1",
		ResolvedRoles: &rolestore.User{
			ID:          "user-1",
			Permissions: []string{"hosts-view"},
		},
	})

	api := &stubPermissionUserAPI{}
	pe := &PermissionEngine{
		userAPI:        api,
		sessionService: cache,
		sessionBaseURL: "https://privx.example.com",
		sourceType:     "AD",
	}

	fake := testconn.New(t)

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice", Connector: fake}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("host-list")
	nextCalled := false
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalled = true
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("expected successful call, got %#v", result)
	}
	if !nextCalled {
		t.Fatal("expected handler to run")
	}
	if api.searchCalls != 0 {
		t.Fatalf("expected no SearchAllUsers call on cache hit, got %d", api.searchCalls)
	}
	if api.resolveCalls != 0 {
		t.Fatalf("expected no ResolveUserRoles call on cache hit, got %d", api.resolveCalls)
	}
}

func TestActiveRolesAt_OmitsInactiveTimeWindow(t *testing.T) {
	at := testTimeUTC(t, "2026-07-07T09:30:00Z") // Tuesday
	user := &rolestore.User{
		Roles: []rolestore.Role{
			{
				ID:   "role-weekday",
				Name: "weekday-only",
				Context: rolestore.ContextualLimit{
					Enabled:  true,
					Validity: []string{"MON", "WED"},
				},
			},
			{
				ID:   "role-always",
				Name: "always-on",
				Context: rolestore.ContextualLimit{
					Enabled: false,
				},
			},
		},
	}

	got := activeRolesAt(user, at)
	if len(got) != 1 || got[0].Name != "always-on" || got[0].ID != "role-always" {
		t.Fatalf("expected only always-on role, got %v", got)
	}
}

// TestToolFilter_HidesScopedToolsWithoutIdentity verifies that the list-time
// tool filter hides permission-scoped tools when no identity is present, while
// always showing public (no-requirement) tools.
func TestToolFilter_HidesScopedToolsWithoutIdentity(t *testing.T) {
	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "scoped-tool",
		RequiredPermissions: []string{"hosts-view"},
	})
	reg.Register(registry.Tool{
		Name: "public-tool",
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		NewPermissionEngine(),
		stubClaimsSource{},
	)

	tools := []*mcp.Tool{
		{Name: "scoped-tool", Description: "scoped", InputSchema: map[string]any{"type": "object"}},
		{Name: "public-tool", Description: "public", InputSchema: map[string]any{"type": "object"}},
		{Name: "unregistered-tool", Description: "unknown", InputSchema: map[string]any{"type": "object"}},
	}

	// No identity in context: scoped tools hidden, public tools visible.
	got := core.filterListedTools(context.Background(), tools)

	names := make(map[string]struct{}, len(got))
	for _, tool := range got {
		names[tool.Name] = struct{}{}
	}

	if _, ok := names["scoped-tool"]; ok {
		t.Fatal("expected scoped-tool to be hidden when identity is missing")
	}
	if _, ok := names["unregistered-tool"]; ok {
		t.Fatal("expected unregistered tool to be hidden")
	}
	if _, ok := names["public-tool"]; !ok {
		t.Fatal("expected public-tool to remain visible without identity")
	}
}

// TestToolFilter_ResolvesPrivXContextOnce verifies that tools/list resolves
// the identity to PrivX roles a single time and reuses it for every tool.
func TestToolFilter_ResolvesPrivXContextOnce(t *testing.T) {
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
		userAPI:    api,
		sourceType: "AD",
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		RequiredPermissions: []string{"hosts-view"},
	})
	reg.Register(registry.Tool{
		Name:                "host-get",
		RequiredPermissions: []string{"hosts-view"},
	})
	reg.Register(registry.Tool{
		Name:                "host-search",
		RequiredPermissions: []string{"hosts-view"},
	})
	reg.Register(registry.Tool{
		Name:                "echo",
		RequiredPermissions: []string{registry.PermissionAuthenticated},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	tools := []*mcp.Tool{
		{Name: "host-list", InputSchema: map[string]any{"type": "object"}},
		{Name: "host-get", InputSchema: map[string]any{"type": "object"}},
		{Name: "host-search", InputSchema: map[string]any{"type": "object"}},
		{Name: "echo", InputSchema: map[string]any{"type": "object"}},
	}

	got := core.filterListedTools(context.Background(), tools)
	if len(got) != 4 {
		t.Fatalf("expected all 4 tools visible, got %d", len(got))
	}
	if api.searchCalls != 1 {
		t.Fatalf("expected one PrivX user search for tools/list, got %d", api.searchCalls)
	}
	if api.resolveCalls != 1 {
		t.Fatalf("expected one PrivX role resolve for tools/list, got %d", api.resolveCalls)
	}
}

// TestToolFilter_ShowsAuthenticatedScope verifies that a tool whose only
// requirement is the "authenticated" scope is shown to any verified identity.
func TestToolFilter_ShowsAuthenticatedScope(t *testing.T) {
	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "my-roles",
		RequiredPermissions: []string{registry.PermissionAuthenticated},
	})

	identity := &oauth.IdentityClaims{Subject: "user", Email: "alice@example.com"}
	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		NewPermissionEngine(),
		stubClaimsSource{claims: identity},
	)

	tools := []*mcp.Tool{{Name: "my-roles", Description: "mine", InputSchema: map[string]any{"type": "object"}}}

	// With identity in context: authenticated-scope tool is visible.
	ctx := oauth.ContextWithClaims(context.Background(), identity)
	got := core.filterListedTools(ctx, tools)
	if len(got) != 1 || got[0].Name != "my-roles" {
		t.Fatalf("expected my-roles to be visible to authenticated user, got %v", got)
	}

	// Without identity: authenticated-scope tool is hidden.
	core2 := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		NewPermissionEngine(),
		stubClaimsSource{},
	)
	got = core2.filterListedTools(context.Background(), tools)
	if len(got) != 0 {
		t.Fatalf("expected my-roles to be hidden without identity, got %v", got)
	}
}

func TestAuthMiddleware_AllowsAfterOnDenyRefresh(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
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
		refreshCooldown: time.Minute,
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("host-list")

	nextCalled := false
	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		nextCalled = true
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("expected refreshed call to allow, got %#v", result)
	}
	if !nextCalled {
		t.Fatal("expected handler to run after refresh granted the scope")
	}
}

func TestAuthMiddleware_CooldownSkipDoesNotNotify(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
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

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "host-list",
		RequiredPermissions: []string{"hosts-view"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("host-list")

	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("handler should not run when still unauthorized")
		return okCallResult(), nil
	})

	first, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error on first call, got: %v", err)
	}
	if first == nil || !first.IsError {
		t.Fatalf("expected first call to deny after refresh, got %#v", first)
	}
	assertScopeDeniedJSON(t, first, "host-list", "not_authorized")

	second, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error on second call, got: %v", err)
	}
	if second == nil || !second.IsError {
		t.Fatalf("expected second call to deny inside cooldown, got %#v", second)
	}
}

func TestAuthMiddleware_RolesChangedReturnsRestartJSON(t *testing.T) {
	identity := &oauth.IdentityClaims{
		Issuer:  "https://issuer.example.com",
		Subject: "subject-1",
		Email:   "alice@example.com",
	}
	now := testTimeUTC(t, "2026-07-09T10:00:00Z")
	cache := session.NewServiceWithClock(30*time.Second, func() time.Time { return now })
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

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "role-list",
		RequiredPermissions: []string{"roles-view"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("role-list")

	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("handler should not run after roles changed")
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected roles-changed deny, got %#v", result)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected error content")
	}

	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %#v", result.Content[0])
	}
	if !strings.Contains(text.Text, `"error":"roles_changed"`) {
		t.Fatalf("expected roles_changed JSON, got %q", text.Text)
	}
	if !strings.Contains(text.Text, `"action":"restart_host_application"`) {
		t.Fatalf("expected restart action in JSON, got %q", text.Text)
	}
	if !strings.Contains(text.Text, scopeDeniedRestartMessage) {
		t.Fatalf("expected restart message in JSON, got %q", text.Text)
	}
	if !strings.Contains(text.Text, `"tool":"role-list"`) {
		t.Fatalf("expected tool name in JSON, got %q", text.Text)
	}
}

func TestAuthMiddleware_CacheMissDenyReturnsRestartJSON(t *testing.T) {
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
			"user-1": {
				Roles:       []rolestore.Role{{Name: "privx-user"}},
				Permissions: []string{"users-view"},
			},
		},
	}
	pe := &PermissionEngine{
		userAPI:         api,
		sessionService:  session.NewService(30 * time.Second),
		sessionBaseURL:  "https://privx.example.com",
		sourceType:      "AD",
		refreshCooldown: time.Minute,
	}

	reg := registry.NewRegistry()
	reg.Register(registry.Tool{
		Name:                "access-group-list",
		RequiredPermissions: []string{"access-groups-manage"},
		InputSchema:         map[string]any{"type": "object"},
		Handler: func(context.Context, map[string]any) (*registry.ToolResult, error) {
			return &registry.ToolResult{Content: []registry.ContentBlock{{Type: "text", Text: "ok"}}}, nil
		},
	})

	core := NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuth{authCtx: &auth.AuthContext{Username: "alice"}},
		reg,
		pe,
		stubClaimsSource{claims: identity},
	)

	request := testCallRequest("access-group-list")

	handler := core.authMiddleware(func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		t.Fatal("handler should not run when unauthorized")
		return okCallResult(), nil
	})

	result, err := handler(context.Background(), request)
	if err != nil {
		t.Fatalf("expected no middleware error, got: %v", err)
	}
	assertScopeDeniedJSON(t, result, "access-group-list", "not_authorized")
}

func assertScopeDeniedJSON(t *testing.T, result *mcp.CallToolResult, toolName, errorCode string) {
	t.Helper()

	if result == nil || !result.IsError {
		t.Fatalf("expected error result, got %#v", result)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected error content")
	}

	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %#v", result.Content[0])
	}
	if !strings.Contains(text.Text, `"error":"`+errorCode+`"`) {
		t.Fatalf("expected error %q in JSON, got %q", errorCode, text.Text)
	}
	if !strings.Contains(text.Text, `"tool":"`+toolName+`"`) {
		t.Fatalf("expected tool %q in JSON, got %q", toolName, text.Text)
	}
	if !strings.Contains(text.Text, `"action":"restart_host_application"`) {
		t.Fatalf("expected restart action in JSON, got %q", text.Text)
	}
	if !strings.Contains(text.Text, scopeDeniedRestartMessage) {
		t.Fatalf("expected restart message in JSON, got %q", text.Text)
	}
}
