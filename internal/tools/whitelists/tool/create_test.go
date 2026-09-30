package tool

import (
	"encoding/json"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreateWhitelistHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/host-store/api/v1/whitelists", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var wl hoststore.Whitelist
		if err := json.Unmarshal(raw, &wl); err != nil {
			t.Fatalf("unmarshal whitelist: %v", err)
		}
		if wl.Name != "my-wl" {
			t.Errorf("name = %q, want my-wl", wl.Name)
		}
		if wl.Type != "glob" {
			t.Errorf("type = %q, want glob", wl.Type)
		}
		if len(wl.WhiteListPatterns) == 0 {
			t.Errorf("whitelist_patterns empty, want non-empty")
		}
		return response.Identifier{ID: "new-wl"}, nil
	})

	res, err := createHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":               "my-wl",
		"type":               "glob",
		"whitelist_patterns": []any{"*"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-wl" {
		t.Errorf("id = %v, want new-wl", m["id"])
	}
}
