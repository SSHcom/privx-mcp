package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetConnectionHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/connection-manager/api/v1/connections/:id", func(body any) (any, error) {
		return connectionmanager.Connection{ID: "c1"}, nil
	})
	res, err := getConnectionHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "c1" {
		t.Errorf("id = %v", m["id"])
	}
}

func TestGetConnectionHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getConnectionHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
