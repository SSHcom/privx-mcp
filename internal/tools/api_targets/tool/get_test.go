package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetAPITargetHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/api-proxy/api/v1/api-targets/:id", func(body any) (any, error) {
		return apiproxy.ApiTarget{ID: "at1", Name: "payments"}, nil
	})
	res, err := getAPITargetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "at1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "at1" {
		t.Errorf("id = %v", m["id"])
	}
}

func TestGetAPITargetHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getAPITargetHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
