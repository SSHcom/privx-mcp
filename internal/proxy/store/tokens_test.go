package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKey_DiffersByInputs(t *testing.T) {
	t.Parallel()

	a := Key("http://mcp/mcp", "http://mcp/mcp", "client")
	b := Key("http://mcp/other", "http://mcp/mcp", "client")
	c := Key("http://mcp/mcp", "http://mcp/mcp", "other")

	if a == b || a == c {
		t.Fatalf("keys should differ: %s %s %s", a, b, c)
	}

	if Key("http://mcp/mcp", "http://mcp/mcp", "client") != a {
		t.Fatal("same inputs must produce the same key")
	}
}

func TestTokens_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := Key("https://mcp.example/mcp", "https://mcp.example/mcp", "proxy")
	exp := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	in := Tokens{
		AccessToken:  "at",
		TokenType:    "Bearer",
		RefreshToken: "rt",
		ExpiresAt:    exp,
	}

	if err := Save(dir, key, in); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, key+"_tokens.json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", st.Mode().Perm())
	}

	got, err := Load(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	if got.AccessToken != "at" || got.RefreshToken != "rt" || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("got %+v", got)
	}
}

func TestLoad_Missing(t *testing.T) {
	t.Parallel()

	_, err := Load(t.TempDir(), "missing")
	if err == nil {
		t.Fatal("error = nil")
	}
}

func TestTokens_UsableSkew(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tok := Tokens{AccessToken: "at", ExpiresAt: now.Add(61 * time.Second)}
	if !tok.Usable(now) {
		t.Fatal("want usable")
	}

	tok.ExpiresAt = now.Add(60 * time.Second)
	if tok.Usable(now) {
		t.Fatal("want stale at 60s skew")
	}

	tok.AccessToken = ""
	tok.ExpiresAt = now.Add(time.Hour)
	if tok.Usable(now) {
		t.Fatal("empty access token must not be usable")
	}
}

func TestDir_EnvOverride(t *testing.T) {
	t.Setenv(EnvAuthDir, "/tmp/proxy-auth-test")

	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}

	if got != "/tmp/proxy-auth-test" {
		t.Fatalf("Dir() = %q", got)
	}
}
