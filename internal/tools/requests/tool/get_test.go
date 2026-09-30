package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetRequestHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(body any) (any, error) {
		return workflow.AccessRequest{ID: "req-1", Status: "WAITING"}, nil
	})
	res, err := getRequestHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "req-1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "req-1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["status"] != "WAITING" {
		t.Errorf("status = %v", m["status"])
	}
}

func TestGetRequestHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getRequestHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetRequestHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := getRequestHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "req-1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch access request") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
