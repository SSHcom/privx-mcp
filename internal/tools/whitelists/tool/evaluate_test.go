package tool

import (
	"encoding/json"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestEvaluateWhitelistHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/whitelists/:id", func(body any) (any, error) {
		return hoststore.Whitelist{ID: "w1", Name: "wl1", Type: "glob"}, nil
	})

	var capturedBody map[string]any
	conn.Handle("POST", "/host-store/api/v1/whitelists/evaluate", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		if err := json.Unmarshal(raw, &capturedBody); err != nil {
			t.Fatalf("unmarshal evaluate body: %v", err)
		}
		return nil, nil
	})

	res, err := evaluateHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":       "w1",
		"commands": []any{"ls"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	if capturedBody == nil {
		t.Fatal("evaluate POST body not captured")
	}
	got, ok := capturedBody["rshell_variant"].(string)
	if !ok {
		t.Fatalf("rshell_variant not a string in body; keys=%v", mapKeys(capturedBody))
	}
	if got != "bash" {
		t.Errorf("rshell_variant = %q, want bash (defaulted)", got)
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
