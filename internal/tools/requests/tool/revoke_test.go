package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestRevokeRequestRoleHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/workflow-engine/api/v1/requests/:id/role/revoke", func(body any) (any, error) {
		return nil, nil
	})
	res, err := revokeRequestRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "req-1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "req-1" || m["revoked"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestRevokeRequestRoleHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := revokeRequestRoleHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestRevokeRequestRoleHandler_RevokeFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/workflow-engine/api/v1/requests/:id/role/revoke", func(body any) (any, error) {
		return nil, errors.New("revoke failed")
	})
	res, err := revokeRequestRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "req-1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to revoke target role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
