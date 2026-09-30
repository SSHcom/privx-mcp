package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetup_DebugWritesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	cleanup, err := Setup(path, "debug")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	Debug("debug-line", "k", "v")
	Info("info-line")
	Warn("warn-line")
	cleanup()

	body := readFile(t, path)
	if !strings.Contains(body, "debug-line") {
		t.Fatalf("expected debug line in %q, got:\n%s", path, body)
	}
	if !strings.Contains(body, "info-line") {
		t.Fatalf("expected info line in %q, got:\n%s", path, body)
	}
	if !strings.Contains(body, "warn-line") {
		t.Fatalf("expected warn line in %q, got:\n%s", path, body)
	}
}

func TestSetup_ErrorOmitsInfoAndDebug(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	cleanup, err := Setup(path, "error")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	Debug("should-not-debug")
	Info("should-not-info")
	Warn("should-not-warn")
	Error("error-line")
	cleanup()

	body := readFile(t, path)
	if strings.Contains(body, "should-not-debug") || strings.Contains(body, "should-not-info") || strings.Contains(body, "should-not-warn") {
		t.Fatalf("warn/info/debug should be filtered at error level, got:\n%s", body)
	}
	if !strings.Contains(body, "error-line") {
		t.Fatalf("expected error line in %q, got:\n%s", path, body)
	}
}

func TestSetup_InfoIncludesWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	cleanup, err := Setup(path, "info")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	Debug("should-not-debug")
	Warn("warn-line")
	Info("info-line")
	cleanup()

	body := readFile(t, path)
	if strings.Contains(body, "should-not-debug") {
		t.Fatalf("debug should be filtered at info level, got:\n%s", body)
	}
	if !strings.Contains(body, "warn-line") {
		t.Fatalf("expected warn line at info level, got:\n%s", body)
	}
	if !strings.Contains(body, "info-line") {
		t.Fatalf("expected info line in %q, got:\n%s", path, body)
	}
}

func TestSetup_WarnOmitsInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	cleanup, err := Setup(path, "warn")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	Debug("should-not-debug")
	Info("should-not-info")
	Warn("warn-line")
	Error("error-line")
	cleanup()

	body := readFile(t, path)
	if strings.Contains(body, "should-not-debug") || strings.Contains(body, "should-not-info") {
		t.Fatalf("info/debug should be filtered at warn level, got:\n%s", body)
	}
	if !strings.Contains(body, "warn-line") {
		t.Fatalf("expected warn line in %q, got:\n%s", path, body)
	}
	if !strings.Contains(body, "error-line") {
		t.Fatalf("expected error line in %q, got:\n%s", path, body)
	}
}

func TestSetup_EmptyFileUsesStdout(t *testing.T) {
	cleanup, err := Setup("", "info")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cleanup()
}

func TestSetup_InvalidLevel(t *testing.T) {
	_, err := Setup("", "trace")
	if err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestSetup_RotatesWhenMaxSizeExceeded(t *testing.T) {
	prevSize := maxSizeMB
	maxSizeMB = 1
	t.Cleanup(func() { maxSizeMB = prevSize })

	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	cleanup, err := Setup(path, "info")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	payload := strings.Repeat("x", 32*1024)
	for i := 0; i < 50; i++ {
		Info("rotate", "n", i, "p", payload)
	}
	cleanup()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) < 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected rotated backup beside app.log, got %v", names)
	}

	current, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat active log: %v", err)
	}
	if current.Size() == 0 {
		t.Fatal("active log file is empty after rotation")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return string(b)
}
