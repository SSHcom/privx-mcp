package tool

import (
	"encoding/json"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreateAccessGroupHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/authorizer/api/v1/accessgroups", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var ag authorizer.AccessGroup
		if err := json.Unmarshal(raw, &ag); err != nil {
			t.Fatalf("unmarshal access group: %v", err)
		}
		if ag.Name != "my-group" {
			t.Errorf("name = %q, want my-group", ag.Name)
		}
		return response.Identifier{ID: "new-ag"}, nil
	})

	res, err := createHandler(testconn.CtxWithAuth(conn), map[string]any{"name": "my-group"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-ag" {
		t.Errorf("id = %v, want new-ag", m["id"])
	}
}
