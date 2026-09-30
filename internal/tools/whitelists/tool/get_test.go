package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetWhitelistHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/whitelists/:id", func(body any) (any, error) {
		return hoststore.Whitelist{ID: "w1", Name: "wl1"}, nil
	})
	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "w1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "w1" {
		t.Errorf("id = %v, want w1", m["id"])
	}
}

func TestGetWhitelistHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
