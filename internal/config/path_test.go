package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigPath_UsesEnvVarWhenSet(t *testing.T) {
	want := filepath.Join(t.TempDir(), "from-env.toml")
	if err := os.WriteFile(want, []byte(""), 0o644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}
	t.Setenv("PRIVX_MCP_CONFIG", want)

	got := ResolveConfigPath(DefaultConfigFileName)
	if got != want {
		t.Fatalf("ResolveConfigPath() = %q, want %q", got, want)
	}
}

func TestResolveConfigPath_UsesConfigFlagWhenEnvUnset(t *testing.T) {
	t.Setenv("PRIVX_MCP_CONFIG", "")

	want := filepath.Join(t.TempDir(), "from-cli.toml")
	if err := os.WriteFile(want, []byte(""), 0o644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"privx-mcp-server", ConfigFlagName, want}

	got := ResolveConfigPath(DefaultConfigFileName)
	if got != want {
		t.Fatalf("ResolveConfigPath() = %q, want %q", got, want)
	}
}

func TestResolveConfigPath_UsesConfigFlagEqualsForm(t *testing.T) {
	t.Setenv("PRIVX_MCP_CONFIG", "")

	want := filepath.Join(t.TempDir(), "from-cli-eq.toml")
	if err := os.WriteFile(want, []byte(""), 0o644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"privx-mcp-server", ConfigFlagName + "=" + want}

	got := ResolveConfigPath(DefaultConfigFileName)
	if got != want {
		t.Fatalf("ResolveConfigPath() = %q, want %q", got, want)
	}
}

func TestResolveConfigPath_EnvVarTakesPrecedenceOverConfigFlag(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), "from-env.toml")
	if err := os.WriteFile(envPath, []byte(""), 0o644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}
	t.Setenv("PRIVX_MCP_CONFIG", envPath)

	cliPath := filepath.Join(t.TempDir(), "from-cli.toml")
	if err := os.WriteFile(cliPath, []byte(""), 0o644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"privx-mcp-server", ConfigFlagName, cliPath}

	got := ResolveConfigPath(DefaultConfigFileName)
	if got != envPath {
		t.Fatalf("ResolveConfigPath() = %q, want env path %q", got, envPath)
	}
}

func TestResolveConfigPath_FindsFileInCurrentWorkingDirectory(t *testing.T) {
	t.Setenv("PRIVX_MCP_CONFIG", "")

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, DefaultConfigFileName)
	if err := os.WriteFile(configPath, []byte(""), 0o644); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}

	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("os.Chdir() failed: %v", err)
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"privx-mcp-server"}

	got := ResolveConfigPath(DefaultConfigFileName)
	if got != configPath {
		t.Fatalf("ResolveConfigPath() = %q, want %q", got, configPath)
	}
}

func TestResolveConfigPath_ReturnsEmptyWhenNotFound(t *testing.T) {
	t.Setenv("PRIVX_MCP_CONFIG", "")

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	wd := t.TempDir()
	if err := os.Chdir(wd); err != nil {
		t.Fatalf("os.Chdir() failed: %v", err)
	}

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"privx-mcp-server"}

	if got := ResolveConfigPath(DefaultConfigFileName); got != "" {
		t.Fatalf("ResolveConfigPath() = %q, want empty", got)
	}
}
