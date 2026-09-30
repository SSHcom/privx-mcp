package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileExists_RegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}
	if !FileExists(path) {
		t.Fatalf("FileExists(%q) = false, want true", path)
	}
}

func TestFileExists_MissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-file")
	if FileExists(missing) {
		t.Fatalf("FileExists(%q) = true, want false", missing)
	}
}

func TestFileExists_DirectoryIsNotAFile(t *testing.T) {
	dir := t.TempDir()
	if FileExists(dir) {
		t.Fatalf("FileExists(%q) = true for a directory, want false", dir)
	}
}

func TestFileExists_EmptyPath(t *testing.T) {
	if FileExists("") {
		t.Fatal("FileExists(\"\") = true, want false")
	}
}
