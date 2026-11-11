package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
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

	if Key("http://mcp/mcp/", "http://mcp/mcp/", "client") != a {
		t.Fatal("trailing slash must not change the key")
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

func TestDeleteIfRefreshToken_KeepsReplacement(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := "session"
	saved := Tokens{
		AccessToken:  "at-new",
		RefreshToken: "rt-new",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := Save(dir, key, saved); err != nil {
		t.Fatal(err)
	}

	if err := DeleteIfRefreshToken(dir, key, "rt-old"); err != nil {
		t.Fatal(err)
	}

	got, err := Load(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	if got.RefreshToken != "rt-new" {
		t.Fatalf("refresh = %q", got.RefreshToken)
	}

	if err := DeleteIfRefreshToken(dir, key, "rt-new"); err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir, key)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("load = %v", err)
	}

	if err := DeleteIfRefreshToken(dir, key, "rt-new"); err != nil {
		t.Fatal(err)
	}
}

func TestWithLock_Serializes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	key := "session"
	started := make(chan struct{})
	release := make(chan struct{})

	var order []string

	var mu sync.Mutex

	firstDone := make(chan error, 1)

	go func() {
		firstDone <- WithLock(dir, key, func() error {
			close(started)
			<-release

			mu.Lock()
			order = append(order, "first")
			mu.Unlock()

			return nil
		})
	}()

	<-started

	entering := make(chan struct{})
	secondDone := make(chan error, 1)

	go func() {
		close(entering)

		secondDone <- WithLock(dir, key, func() error {
			mu.Lock()
			order = append(order, "second")
			mu.Unlock()

			return nil
		})
	}()

	<-entering

	select {
	case err := <-secondDone:
		t.Fatalf("second lock returned while first was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}

	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("order = %v", order)
	}
}

func TestSaveAndLock_TightenDirectoryMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Save(dir, "session", Tokens{
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	assertDirMode(t, dir, 0o700)

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := WithLock(dir, "session", func() error { return nil }); err != nil {
		t.Fatal(err)
	}

	assertDirMode(t, dir, 0o700)
}

func assertDirMode(t *testing.T, dir string, want os.FileMode) {
	t.Helper()

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	if st.Mode().Perm() != want {
		t.Fatalf("mode = %o, want %o", st.Mode().Perm(), want)
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
