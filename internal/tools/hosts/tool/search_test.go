package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestSearchHostsHandler(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("POST", "/host-store/api/v1/hosts/search", func(body any) (any, error) {
			raw, _ := json.Marshal(body)
			var hs hoststore.HostSearch
			_ = json.Unmarshal(raw, &hs)
			if hs.Keywords != "web" {
				t.Errorf("search body keywords = %q, want web", hs.Keywords)
			}
			return response.ResultSet[hoststore.Host]{
				Count: 1,
				Items: []hoststore.Host{{ID: "h1", CommonName: "web1"}},
			}, nil
		})
		res, err := searchHostsHandler(testconn.CtxWithAuth(conn), map[string]any{
			"search": map[string]any{"keywords": "web"},
			"limit":  float64(10),
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", res.Content[0].Text)
		}
		m := testconn.DecodeResult(t, res.Content[0].Text)
		if m["count"].(float64) != 1 {
			t.Errorf("count = %v", m["count"])
		}
	})

	t.Run("disabled_boolean_rejected", func(t *testing.T) {
		conn := testconn.New(t)
		res, err := searchHostsHandler(testconn.CtxWithAuth(conn), map[string]any{
			"search": map[string]any{"disabled": true},
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected error for boolean disabled")
		}
		if !strings.Contains(res.Content[0].Text, "invalid search body") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})
}
