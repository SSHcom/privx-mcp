package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
)

// --- Mock implementations ---

type mockConnect struct {
	connector restapi.Connector
	username  string
	err       error
	gotCfg    *config.Config
	gotClaims *oauth.IdentityClaims
}

func (m *mockConnect) Connect(_ context.Context, cfg *config.Config, claims *oauth.IdentityClaims) (restapi.Connector, string, error) {
	m.gotCfg = cfg
	m.gotClaims = claims
	return m.connector, m.username, m.err
}

// mockConnector is a minimal connector implementation for testing.
type mockConnector struct{}

func (m *mockConnector) URL(path string, args ...interface{}) restapi.CURL { return nil }

// --- Tests ---

func TestAuthenticate_Success(t *testing.T) {
	conn := &mockConnector{}
	cfg := &config.Config{
		OAuth: config.OAuthConfig{
			IdentityClaimField:  "email",
			IdentityMappingRule: "strip-domain",
		},
	}
	claims := &oauth.IdentityClaims{
		Subject: "user-123",
		Email:   "alice@example.com",
		Issuer:  "https://idp.example.com",
	}
	mockConn := &mockConnect{connector: conn, username: "alice"}
	authenticator := NewAuthenticator(cfg).(*mcpAuthenticator)
	authenticator.connect = mockConn.Connect

	ctx := context.Background()
	authCtx, err := authenticator.Authenticate(ctx, claims)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if authCtx.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", authCtx.Username)
	}
	if authCtx.Connector == nil {
		t.Error("expected non-nil connector")
	}
	if len(authCtx.Roles) != 0 {
		t.Errorf("expected empty roles, got %v", authCtx.Roles)
	}
	if mockConn.gotCfg != cfg {
		t.Error("expected config to be passed to ConnectWithExternalJWT")
	}
	if mockConn.gotClaims != claims {
		t.Error("expected claims to be passed to ConnectWithExternalJWT")
	}
}

func TestAuthenticate_NilClaimsReturnsAuthError(t *testing.T) {
	cfg := &config.Config{
		OAuth: config.OAuthConfig{IdentityClaimField: "email", IdentityMappingRule: "as-is"},
	}
	authenticator := NewAuthenticator(cfg)

	ctx := context.Background()
	_, err := authenticator.Authenticate(ctx, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if authErr.Message == "" {
		t.Error("expected non-empty AuthError message")
	}
}

func TestAuthenticate_PrivXConnectError(t *testing.T) {
	cfg := &config.Config{
		OAuth: config.OAuthConfig{IdentityClaimField: "email", IdentityMappingRule: "as-is"},
	}
	mockConn := &mockConnect{err: errors.New("connectivity problem")}
	authenticator := NewAuthenticator(cfg).(*mcpAuthenticator)
	authenticator.connect = mockConn.Connect

	ctx := context.Background()
	_, err := authenticator.Authenticate(ctx, &oauth.IdentityClaims{Email: "alice@example.com"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expected := "privx connection failed: connectivity problem"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestAuthenticate_RequiresConfig(t *testing.T) {
	authenticator := NewAuthenticator(nil)

	ctx := context.Background()
	_, err := authenticator.Authenticate(ctx, &oauth.IdentityClaims{Email: "alice@example.com"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expected := "auth config is required"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestAuthenticate_PipelineStopsOnNilClaims(t *testing.T) {
	cfg := &config.Config{
		OAuth: config.OAuthConfig{IdentityClaimField: "email", IdentityMappingRule: "as-is"},
	}
	mockConn := &mockConnect{connector: &mockConnector{}}
	authenticator := NewAuthenticator(cfg).(*mcpAuthenticator)
	authenticator.connect = mockConn.Connect

	ctx := context.Background()
	_, err := authenticator.Authenticate(ctx, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if mockConn.gotClaims != nil {
		t.Error("expected connect not to be called when claims are nil")
	}
}
