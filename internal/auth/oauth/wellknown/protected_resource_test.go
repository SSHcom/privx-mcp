package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterRoutesValidatesInput(t *testing.T) {
	tests := []struct {
		name string
		cfg  ProtectedResourceConfig
	}{
		{"missing resource", ProtectedResourceConfig{AuthorizationServers: []string{"https://issuer"}}},
		{"missing authorization servers", ProtectedResourceConfig{Resource: "http://localhost:8181/mcp"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := RegisterRoutes(http.NewServeMux(), tc.cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
	if err := RegisterRoutes(nil, ProtectedResourceConfig{Resource: "x", AuthorizationServers: []string{"y"}}); err == nil {
		t.Fatal("expected nil mux error")
	}
}

func TestProtectedResourceMetadataBody(t *testing.T) {
	mux := http.NewServeMux()
	cfg := ProtectedResourceConfig{
		Resource:             "http://localhost:8181/mcp",
		AuthorizationServers: []string{"http://localhost:8080/realms/mcp"},
	}
	if err := RegisterRoutes(mux, cfg); err != nil {
		t.Fatalf("expected RegisterRoutes success: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, ProtectedResourceURL, http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json content-type, got %q", ct)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
	if body["resource"] != cfg.Resource {
		t.Fatalf("expected resource %q, got %#v", cfg.Resource, body["resource"])
	}
	servers, ok := body["authorization_servers"].([]any)
	if !ok || len(servers) != 1 || servers[0] != cfg.AuthorizationServers[0] {
		t.Fatalf("expected authorization_servers %#v, got %#v", cfg.AuthorizationServers, body["authorization_servers"])
	}
}

func TestProtectedResourceMetadataRejectsNonGet(t *testing.T) {
	mux := http.NewServeMux()
	if err := RegisterRoutes(mux, ProtectedResourceConfig{
		Resource:             "http://localhost:8181/mcp",
		AuthorizationServers: []string{"http://localhost:8080/realms/mcp"},
	}); err != nil {
		t.Fatalf("expected RegisterRoutes success: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, ProtectedResourceURL, http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}
