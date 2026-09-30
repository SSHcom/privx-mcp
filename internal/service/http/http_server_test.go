package http

import (
	stdhttp "net/http"
	"testing"
)

func TestNewRequiresHandler(t *testing.T) {
	_, _, err := NewHTTPServer(Options{})
	if err == nil {
		t.Fatal("expected error when handler is missing")
	}
}

func TestNewReturnsCleanup(t *testing.T) {
	_, cleanup, err := NewHTTPServer(Options{
		Addr:    "127.0.0.1:0",
		Handler: stdhttp.NewServeMux(),
	})
	if err != nil {
		t.Fatalf("expected server creation success: %v", err)
	}
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup")
	}
	cleanup()
}
