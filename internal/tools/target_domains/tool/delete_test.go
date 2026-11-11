package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeleteTargetDomainHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("DELETE", "/secrets-manager/api/v1/targetdomains/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "td1" {
		t.Errorf("id = %v, want td1", m["id"])
	}
	if m["deleted"] != true {
		t.Errorf("deleted = %v, want true", m["deleted"])
	}
}

func TestDeleteTargetDomainHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
