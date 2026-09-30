package oauth

import (
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/proxy/config"
)

func TestRedirectURIAndBindHost(t *testing.T) {
	t.Parallel()

	cb := config.CallbackConfig{
		Host: "localhost",
		Port: 3334,
		Path: "/oauth/callback",
	}

	if got := RedirectURI(cb); got != "http://localhost:3334/oauth/callback" {
		t.Fatalf("RedirectURI = %q", got)
	}

	if got := BindHost("localhost"); got != "127.0.0.1" {
		t.Fatalf("BindHost(localhost) = %q", got)
	}

	if got := BindHost("127.0.0.1"); got != "127.0.0.1" {
		t.Fatalf("BindHost(127.0.0.1) = %q", got)
	}

	if got := listenAddr(cb); got != "127.0.0.1:3334" {
		t.Fatalf("listenAddr = %q", got)
	}
}
