package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
	"github.com/pmsshintegration/privx-mcp/internal/proxy/store"
)

func TestObtain_RequiresConfidentialClient(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		MCPURL: "https://mcp.example/mcp",
		Callback: config.CallbackConfig{
			Host:               "127.0.0.1",
			Port:               1,
			Path:               "/oauth/callback",
			AuthTimeoutSeconds: 5,
		},
	}
	discovered := Result{Resource: "https://mcp.example/mcp"}

	_, err := Obtain(context.Background(), ObtainParams{
		Config:     cfg,
		Discovered: discovered,
		AuthDir:    t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "confidential client") {
		t.Fatalf("err = %v", err)
	}

	cfg.Client.ClientID = "proxy"
	_, err = Obtain(context.Background(), ObtainParams{
		Config:     cfg,
		Discovered: discovered,
		AuthDir:    t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "DCR") {
		t.Fatalf("err = %v", err)
	}
}

func TestObtain_UsesStoredTokens(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := testClientConfig()
	exp := time.Now().Add(time.Hour)
	key := store.Key(cfg.MCPURL, cfg.MCPURL, cfg.Client.ClientID)
	if err := store.Save(dir, key, store.Tokens{
		AccessToken: "stored-at",
		ExpiresAt:   exp,
	}); err != nil {
		t.Fatal(err)
	}

	tok, err := Obtain(context.Background(), ObtainParams{
		Config:     cfg,
		Discovered: Result{Resource: cfg.MCPURL},
		AuthDir:    dir,
		OpenBrowser: func(string) error {
			t.Fatal("browser should not open")

			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if tok.AccessToken != "stored-at" {
		t.Fatalf("access = %q", tok.AccessToken)
	}
}

func TestObtain_ResetSessionIgnoresStoredTokens(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		t.Fatalf("addr type %T", ln.Addr())
	}

	port := addr.Port
	_ = ln.Close()

	dir := t.TempDir()
	cfg := testClientConfig()
	cfg.Callback.Host = "127.0.0.1"
	cfg.Callback.Port = port

	key := store.Key(cfg.MCPURL, cfg.MCPURL, cfg.Client.ClientID)
	if err := store.Save(dir, key, store.Tokens{
		AccessToken: "stored-at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var authURL string

	_, err = Obtain(ctx, ObtainParams{
		Config:       cfg,
		Discovered:   Result{Resource: cfg.MCPURL, AuthorizationEndpoint: "https://idp.example/auth"},
		AuthDir:      dir,
		ResetSession: true,
		OpenBrowser: func(u string) error {
			authURL = u
			cancel()

			return nil
		},
	})
	if err == nil {
		t.Fatal("expected canceled callback")
	}

	stored, loadErr := store.Load(dir, key)
	if loadErr != nil {
		t.Fatal(loadErr)
	}

	if stored.AccessToken != "stored-at" {
		t.Fatalf("access = %q", stored.AccessToken)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}

	if u.Query().Get("prompt") != "login" {
		t.Fatalf("prompt = %q", u.Query().Get("prompt"))
	}
}

func TestObtain_RefreshThenInteractive(t *testing.T) {
	t.Parallel()

	var grants []string

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		grants = append(grants, form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")

		if form.Get("grant_type") == "refresh_token" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "refreshed-at",
				"refresh_token": "new-rt",
				"expires_in":    3600,
			})

			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(tokenSrv.Close)

	dir := t.TempDir()
	cfg := testClientConfig()
	key := store.Key(cfg.MCPURL, cfg.MCPURL, cfg.Client.ClientID)
	if err := store.Save(dir, key, store.Tokens{
		AccessToken:  "old-at",
		RefreshToken: "old-rt",
		ExpiresAt:    time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	tok, err := Obtain(context.Background(), ObtainParams{
		HTTP:   tokenSrv.Client(),
		Config: cfg,
		Discovered: Result{
			Resource:      cfg.MCPURL,
			TokenEndpoint: tokenSrv.URL,
		},
		AuthDir: dir,
		OpenBrowser: func(string) error {
			t.Fatal("browser should not open after refresh")

			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if tok.AccessToken != "refreshed-at" {
		t.Fatalf("access = %q", tok.AccessToken)
	}

	if len(grants) != 1 || grants[0] != "refresh_token" {
		t.Fatalf("grants = %v", grants)
	}
}

func TestObtain_Interactive(t *testing.T) {
	t.Parallel()

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("code") != "live-code" || form.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "interactive-at",
			"expires_in":   120,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		t.Fatalf("addr type %T", ln.Addr())
	}

	port := addr.Port
	_ = ln.Close()

	cfg := testClientConfig()
	cfg.Callback.Host = "127.0.0.1"
	cfg.Callback.Port = port

	tok, err := Obtain(context.Background(), ObtainParams{
		HTTP:   tokenSrv.Client(),
		Config: cfg,
		Discovered: Result{
			Resource:              cfg.MCPURL,
			AuthorizationEndpoint: "http://127.0.0.1/authorize",
			TokenEndpoint:         tokenSrv.URL,
			Scopes:                []string{"openid"},
		},
		AuthDir: t.TempDir(),
		OpenBrowser: func(authURL string) error {
			u, err := url.Parse(authURL)
			if err != nil {
				return err
			}

			state := u.Query().Get("state")
			go func() {
				time.Sleep(50 * time.Millisecond)
				resp, err := http.Get(fmt.Sprintf(
					"http://127.0.0.1:%d/oauth/callback?code=live-code&state=%s",
					port,
					url.QueryEscape(state),
				))
				if err != nil {
					return
				}

				_ = resp.Body.Close()
			}()

			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if tok.AccessToken != "interactive-at" {
		t.Fatalf("access = %q", tok.AccessToken)
	}
}

func testClientConfig() *config.Config {
	return &config.Config{
		MCPURL: "https://mcp.example/mcp",
		Callback: config.CallbackConfig{
			Host:               "localhost",
			Port:               3334,
			Path:               "/oauth/callback",
			AuthTimeoutSeconds: 5,
		},
		Client: config.ClientConfig{
			ClientID:                "proxy",
			ClientSecret:            "s3cret",
			TokenEndpointAuthMethod: "client_secret_post",
		},
	}
}
