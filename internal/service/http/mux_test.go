package http

import (
	stdhttp "net/http"
	"testing"
)

func TestNewMuxRegistersRoutes(t *testing.T) {
	mux, err := NewMux(func(m *stdhttp.ServeMux) error {
		m.HandleFunc("/healthz", func(stdhttp.ResponseWriter, *stdhttp.Request) {})
		return nil
	})
	if err != nil {
		t.Fatalf("expected NewMux to succeed: %v", err)
	}
	if mux == nil {
		t.Fatal("expected mux to be initialized")
	}
}

func TestNewMuxRejectsNilRegistrar(t *testing.T) {
	_, err := NewMux(nil)
	if err == nil {
		t.Fatal("expected nil registrar error")
	}
}
