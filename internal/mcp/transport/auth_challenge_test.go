package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
)

// --- WithBearerVerification ---

type stubVerifier struct {
	claims *oauth.IdentityClaims
	err    error
	gotTok string
}

func (s *stubVerifier) Verify(_ context.Context, rawToken string) (*oauth.IdentityClaims, error) {
	s.gotTok = rawToken
	return s.claims, s.err
}

func TestWithBearerVerification_MissingTokenReturns401(t *testing.T) {
	verifier := &stubVerifier{claims: &oauth.IdentityClaims{Subject: "alice"}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	wrapped := WithBearerVerification("http://localhost:8181", verifier, next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected next handler NOT to be called when bearer is missing")
	}
	if verifier.gotTok != "" {
		t.Fatalf("expected verifier NOT to be called without a token, got token %q", verifier.gotTok)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatal("expected WWW-Authenticate challenge")
	}
}

func TestWithBearerVerification_TrimsTrailingSlashOnMetadataURL(t *testing.T) {
	verifier := &stubVerifier{claims: &oauth.IdentityClaims{Subject: "alice"}}
	wrapped := WithBearerVerification("http://localhost:8181/", verifier, http.NotFoundHandler())

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	want := `Bearer resource_metadata="http://localhost:8181/.well-known/oauth-protected-resource"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("unexpected WWW-Authenticate header:\nwant %q\ngot  %q", want, got)
	}
}

func TestWithBearerVerification_ExpiredTokenReturns401(t *testing.T) {
	verifier := &stubVerifier{err: &oauth.VerificationError{Reason: "expired", Message: "token has expired"}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	wrapped := WithBearerVerification("http://localhost:8181", verifier, next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer expired-jwt")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on expired token, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected next handler NOT to be called when verification fails")
	}
	if verifier.gotTok != "expired-jwt" {
		t.Fatalf("expected verifier to receive the raw token, got %q", verifier.gotTok)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatal("expected WWW-Authenticate challenge on expired token")
	}
}

func TestWithBearerVerification_BadSignatureReturns401(t *testing.T) {
	verifier := &stubVerifier{err: errors.New("signature invalid")}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called on verify failure")
	})

	wrapped := WithBearerVerification("http://localhost:8181", verifier, next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer bad-sig")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad signature, got %d", rec.Code)
	}
}

func TestWithBearerVerification_ValidTokenInjectsClaimsAndForwards(t *testing.T) {
	claims := &oauth.IdentityClaims{Subject: "alice", Email: "alice@example.com"}
	verifier := &stubVerifier{claims: claims}
	var capturedClaims *oauth.IdentityClaims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = oauth.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithBearerVerification("http://localhost:8181", verifier, next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-jwt")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid token, got %d", rec.Code)
	}
	if verifier.gotTok != "valid-jwt" {
		t.Fatalf("expected verifier to receive raw token, got %q", verifier.gotTok)
	}
	if capturedClaims != claims {
		t.Fatalf("expected claims injected into request context, got %#v", capturedClaims)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("expected no WWW-Authenticate on success, got %q", got)
	}
}

func TestWithBearerVerification_NonBearerSchemeReturns401(t *testing.T) {
	verifier := &stubVerifier{claims: &oauth.IdentityClaims{Subject: "alice"}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called for non-Bearer scheme")
	})

	wrapped := WithBearerVerification("http://localhost:8181", verifier, next)

	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Basic dXNlcjpwdw==")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for non-Bearer scheme, got %d", rec.Code)
	}
}
