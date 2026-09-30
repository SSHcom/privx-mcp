package privx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrivXTokenExchanger_NewRequiresBaseURL(t *testing.T) {
	_, err := NewPrivXTokenExchanger(ExchangerConfig{})
	if err == nil {
		t.Fatal("expected error when PrivX base URL is empty")
	}
}

func TestPrivXTokenExchanger_ExchangeSuccess(t *testing.T) {
	// Create a mock PrivX token endpoint that returns a valid access token.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/token/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify the request body contains the token.
		var req struct {
			Token    string `json:"token"`
			Scope    string `json:"scope"`
			ClientId string `json:"client_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		// Return a successful token response.
		resp := map[string]interface{}{
			"access_token": "privx-access-token-12345",
			"token_type":   "bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	exchanger, err := NewPrivXTokenExchanger(ExchangerConfig{
		PrivXBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error creating exchanger: %v", err)
	}

	connector, err := exchanger.Exchange(context.Background(), "test-minted-jwt")
	if err != nil {
		t.Fatalf("unexpected error during exchange: %v", err)
	}
	if connector == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestPrivXTokenExchanger_ExchangeAuthError(t *testing.T) {
	// Create a mock PrivX token endpoint that returns 401.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/token/login" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		resp := map[string]interface{}{
			"error_code":    "unauthorized",
			"error_message": "authentication failed",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	exchanger, err := NewPrivXTokenExchanger(ExchangerConfig{
		PrivXBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error creating exchanger: %v", err)
	}

	_, err = exchanger.Exchange(context.Background(), "bad-jwt")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}

	// Should be classified as an auth error.
	var authErr *ExchangeAuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected ExchangeAuthError, got %T: %v", err, err)
	}
}

func TestPrivXTokenExchanger_ExchangeForbiddenError(t *testing.T) {
	// Create a mock PrivX token endpoint that returns 403.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/token/login" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		resp := map[string]interface{}{
			"error_code":    "forbidden",
			"error_message": "access denied",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	exchanger, err := NewPrivXTokenExchanger(ExchangerConfig{
		PrivXBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error creating exchanger: %v", err)
	}

	_, err = exchanger.Exchange(context.Background(), "bad-jwt")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}

	// Should be classified as an auth error.
	var authErr *ExchangeAuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected ExchangeAuthError, got %T: %v", err, err)
	}
}

func TestPrivXTokenExchanger_ExchangeNetworkError(t *testing.T) {
	// Use an invalid URL that will cause a connection failure.
	exchanger, err := NewPrivXTokenExchanger(ExchangerConfig{
		PrivXBaseURL: "http://127.0.0.1:1", // port 1 should be unreachable
	})
	if err != nil {
		t.Fatalf("unexpected error creating exchanger: %v", err)
	}

	_, err = exchanger.Exchange(context.Background(), "test-jwt")
	if err == nil {
		t.Fatal("expected error for network failure")
	}

	// Should be classified as a network error.
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected NetworkError, got %T: %v", err, err)
	}
}

func TestPrivXTokenExchanger_ExchangeWithoutScope(t *testing.T) {
	// Verify exchanger works without an explicit scope.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/api/v1/token/login" {
			http.NotFound(w, r)
			return
		}

		resp := map[string]interface{}{
			"access_token": "privx-access-token-no-scope",
			"token_type":   "bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	exchanger, err := NewPrivXTokenExchanger(ExchangerConfig{
		PrivXBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error creating exchanger: %v", err)
	}

	connector, err := exchanger.Exchange(context.Background(), "test-jwt")
	if err != nil {
		t.Fatalf("unexpected error during exchange: %v", err)
	}
	if connector == nil {
		t.Fatal("expected non-nil connector")
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"connection refused", "dial tcp 127.0.0.1:1: connect: connection refused", true},
		{"dns failure", "dial tcp: lookup nonexistent.example.com: no such host", true},
		{"timeout", "dial tcp 10.0.0.1:443: i/o timeout", true},
		{"auth error", "error: unauthorized, message: authentication failed", false},
		{"generic error", "something went wrong", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			got := isNetworkError(err)
			if got != tt.expected {
				t.Errorf("isNetworkError(%q) = %v, want %v", tt.errMsg, got, tt.expected)
			}
		})
	}
}

func TestIsAuthRejection(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{"401 status", "HTTP error: 401 Unauthorized", true},
		{"403 status", "HTTP error: 403 Forbidden", true},
		{"unauthorized keyword", "error: unauthorized, message: bad token", true},
		{"forbidden keyword", "error: forbidden, message: access denied", true},
		{"network error", "dial tcp: connection refused", false},
		{"generic error", "something went wrong", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthRejection(tt.errMsg)
			if got != tt.expected {
				t.Errorf("isAuthRejection(%q) = %v, want %v", tt.errMsg, got, tt.expected)
			}
		})
	}
}
