package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestExchangeCode_ClientSecretPost(t *testing.T) {
	t.Parallel()

	var got url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}

		got, err = url.ParseQuery(string(body))
		if err != nil {
			t.Error(err)
		}

		if got.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-1",
			"token_type":    "Bearer",
			"refresh_token": "rt-1",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(srv.Close)

	tok, err := exchangeCode(context.Background(), srv.Client(), exchangeParams{
		TokenURL: srv.URL,
		Auth: clientAuth{
			ClientID:                "proxy",
			ClientSecret:            "s3cret",
			TokenEndpointAuthMethod: "client_secret_post",
		},
		RedirectURI: "http://localhost:3334/oauth/callback",
		Code:        "auth-code",
		Verifier:    "verifier-value",
		Resource:    "http://localhost:8181/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}

	if tok.AccessToken != "at-1" || tok.RefreshToken != "rt-1" {
		t.Fatalf("tokens = %+v", tok)
	}

	if got.Get("grant_type") != "authorization_code" {
		t.Fatalf("grant_type = %q", got.Get("grant_type"))
	}

	if got.Get("code") != "auth-code" || got.Get("code_verifier") != "verifier-value" {
		t.Fatalf("code fields = %v", got)
	}

	if got.Get("resource") != "http://localhost:8181/mcp" {
		t.Fatalf("resource = %q", got.Get("resource"))
	}

	if got.Get("client_id") != "proxy" || got.Get("client_secret") != "s3cret" {
		t.Fatalf("client auth = %v", got)
	}

	if !tok.ExpiresAt.After(time.Now().Add(30 * time.Minute)) {
		t.Fatalf("expires_at = %s", tok.ExpiresAt)
	}
}

func TestExchangeCode_RejectsMissingVerifier(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"x"}`))
	}))
	t.Cleanup(srv.Close)

	_, err := exchangeCode(context.Background(), srv.Client(), exchangeParams{
		TokenURL: srv.URL,
		Auth: clientAuth{
			ClientID:                "proxy",
			ClientSecret:            "s3cret",
			TokenEndpointAuthMethod: "client_secret_post",
		},
		Code: "auth-code",
	})
	if err == nil {
		t.Fatal("error = nil")
	}
}

func TestRefreshTokens_SuccessAndInvalidGrant(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")

		if form.Get("refresh_token") == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-2",
			"expires_in":   60,
		})
	}))
	t.Cleanup(srv.Close)

	auth := clientAuth{
		ClientID:                "proxy",
		ClientSecret:            "s3cret",
		TokenEndpointAuthMethod: "client_secret_post",
	}

	tok, err := refreshTokens(context.Background(), srv.Client(), srv.URL, auth, "good", "http://mcp/mcp")
	if err != nil {
		t.Fatal(err)
	}

	if tok.AccessToken != "at-2" {
		t.Fatalf("access = %q", tok.AccessToken)
	}

	if tok.RefreshToken != "good" {
		t.Fatalf("refresh token should be preserved, got %q", tok.RefreshToken)
	}

	_, err = refreshTokens(context.Background(), srv.Client(), srv.URL, auth, "bad", "http://mcp/mcp")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthorizeURL(t *testing.T) {
	t.Parallel()

	raw, err := authorizeURL(authorizeParams{
		AuthorizationEndpoint: "https://idp.example/auth",
		ClientID:              "proxy",
		RedirectURI:           "http://localhost:3334/oauth/callback",
		Scopes:                []string{"openid", "profile"},
		State:                 "st",
		Challenge:             "ch",
		Resource:              "https://mcp.example/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "proxy",
		"redirect_uri":          "http://localhost:3334/oauth/callback",
		"scope":                 "openid profile",
		"state":                 "st",
		"code_challenge":        "ch",
		"code_challenge_method": "S256",
		"access_type":           "offline",
		"resource":              "https://mcp.example/mcp",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}

	if q.Get("prompt") != "" {
		t.Fatalf("prompt = %q", q.Get("prompt"))
	}
}

// TestExchangeCode_StringExpiresIn covers the Azure AD v1 token endpoint,
// which returns expires_in as a JSON string rather than a number.
func TestExchangeCode_StringExpiresIn(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Note expires_in and refresh-related fields are quoted strings, as
		// emitted by the sts.windows.net (v1) token endpoint.
		_, _ = io.WriteString(w, `{
			"access_token": "at-v1",
			"token_type": "Bearer",
			"refresh_token": "rt-v1",
			"expires_in": "3600",
			"ext_expires_in": "3600"
		}`)
	}))
	t.Cleanup(srv.Close)

	now := time.Now()

	tok, err := exchangeCode(context.Background(), srv.Client(), exchangeParams{
		TokenURL: srv.URL,
		Auth: clientAuth{
			ClientID:                "proxy",
			ClientSecret:            "s3cret",
			TokenEndpointAuthMethod: "client_secret_post",
		},
		RedirectURI: "http://localhost:3334/oauth/callback",
		Code:        "auth-code",
		Verifier:    "verifier-value",
		Resource:    "https://privxmcp.example/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}

	if tok.AccessToken != "at-v1" || tok.RefreshToken != "rt-v1" {
		t.Fatalf("tokens = %+v", tok)
	}

	if !tok.ExpiresAt.After(now.Add(59*time.Minute)) || tok.ExpiresAt.After(now.Add(61*time.Minute)) {
		t.Fatalf("expiresAt = %v, want ~1h from now", tok.ExpiresAt)
	}
}
