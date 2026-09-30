package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeletePasswordPolicyHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("DELETE", "/secrets-manager/api/v1/password-policy/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "pp1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "pp1" {
		t.Errorf("id = %v, want pp1", m["id"])
	}
	if m["deleted"] != true {
		t.Errorf("deleted = %v, want true", m["deleted"])
	}
}

func TestDeletePasswordPolicyHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
