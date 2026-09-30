package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestTerminateConnectionHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/connection-manager/api/v1/terminate/connection/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := terminateConnectionHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
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
	if m["terminated"] != true {
		t.Errorf("terminated = %v, want true", m["terminated"])
	}
}

func TestTerminateConnectionHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := terminateConnectionHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
