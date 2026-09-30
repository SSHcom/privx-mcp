package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeleteRequestHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("DELETE", "/workflow-engine/api/v1/requests/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteRequestHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "req-1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "req-1" || m["deleted"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestDeleteRequestHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteRequestHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteRequestHandler_DeleteFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("DELETE", "/workflow-engine/api/v1/requests/:id", func(body any) (any, error) {
		return nil, errors.New("delete failed")
	})
	res, err := deleteRequestHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "req-1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to delete access request") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
