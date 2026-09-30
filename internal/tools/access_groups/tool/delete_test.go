package tool

import (
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeleteAccessGroupHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("DELETE", "/authorizer/api/v1/accessgroups/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "ag1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "ag1" {
		t.Errorf("id = %v, want ag1", m["id"])
	}
	if m["deleted"] != true {
		t.Errorf("deleted = %v, want true", m["deleted"])
	}
}
