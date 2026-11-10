package privx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pmsshintegration/privx-mcp/internal/config"
)

func TestConnectWithAPICredentials_RequiresConfig(t *testing.T) {
	_, err := ConnectWithAPICredentials(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnectWithAPICredentials_TimeoutKeepsConnector(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	previous := privxHTTPTimeout
	privxHTTPTimeout = 200 * time.Millisecond
	defer func() { privxHTTPTimeout = previous }()

	connector, err := ConnectWithAPICredentials(apiCredentialConfig(server.URL))
	if err != nil {
		t.Fatalf("timeout returned error: %v", err)
	}
	if connector == nil {
		t.Fatal("expected connector after timeout")
	}
}

func TestConnectWithAPICredentials_AuthRejectionStillFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := ConnectWithAPICredentials(apiCredentialConfig(server.URL))
	if err == nil {
		t.Fatal("expected authentication failure")
	}
	if !strings.Contains(err.Error(), "authenticate with api credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func apiCredentialConfig(baseURL string) *config.Config {
	return &config.Config{
		PrivXAuth: config.PrivXAuthConfig{
			PrivXBaseURL:         baseURL,
			APIOAuthClientID:     "oauth-id",
			APIOAuthClientSecret: "oauth-secret",
			APIClientID:          "api-id",
			APIClientSecret:      "api-secret",
		},
	}
}

func TestConnectWithAPICredentials_ValidatesRequiredFields(t *testing.T) {
	cfg := &config.Config{}
	_, err := ConnectWithAPICredentials(cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "auth.privx_base_url is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
