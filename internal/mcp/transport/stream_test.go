package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/runtime"
)

type stubAuthenticator struct{}

func (stubAuthenticator) Authenticate(_ context.Context, _ *oauth.IdentityClaims) (*auth.AuthContext, error) {
	return &auth.AuthContext{}, nil
}

func TestRegisterRoutesValidatesInput(t *testing.T) {
	if err := RegisterRoutes(nil, nil, StreamConfig{}); err == nil {
		t.Fatal("expected nil mux/core validation error")
	}
}

func TestRegisterRoutesMountsMCPPath(t *testing.T) {
	core := runtime.NewCore(
		config.ServerConfig{Name: "test", Version: "test"},
		stubAuthenticator{},
		registry.NewRegistry(),
		runtime.NewPermissionEngine(),
		HTTPClaimsSource{},
	)

	mux := http.NewServeMux()
	if err := RegisterRoutes(mux, core, StreamConfig{
		PublicURL: "http://localhost:8181",
		Verifier:  &stubVerifier{claims: &oauth.IdentityClaims{Subject: "alice"}},
	}); err != nil {
		t.Fatalf("expected RegisterRoutes success: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Fatalf("expected /mcp to be handled, got %d", rec.Code)
	}
}
