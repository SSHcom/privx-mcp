package privx

import (
	"strings"
	"testing"

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
