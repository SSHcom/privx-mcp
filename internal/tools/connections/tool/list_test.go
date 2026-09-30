package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestListConnectionsHandler(t *testing.T) {
	t.Run("no_auth", func(t *testing.T) {
		res, err := listConnectionsHandler(testconn.CtxNoAuth(), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected error result")
		}
		if !strings.Contains(res.Content[0].Text, "authentication error") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})

	t.Run("happy", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("GET", "/connection-manager/api/v1/connections", func(body any) (any, error) {
			return response.ResultSet[connectionmanager.Connection]{
				Count: 2,
				Items: []connectionmanager.Connection{
					{ID: "c1"},
					{ID: "c2"},
				},
			}, nil
		})

		res, err := listConnectionsHandler(testconn.CtxWithAuth(conn), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", res.Content[0].Text)
		}
		m := testconn.DecodeResult(t, res.Content[0].Text)
		if m["count"].(float64) != 2 {
			t.Errorf("count = %v", m["count"])
		}
		if m["limit"].(float64) != float64(common.ConnectionsListLimit) {
			t.Errorf("limit = %v", m["limit"])
		}
		if m["offset"].(float64) != 0 {
			t.Errorf("offset = %v", m["offset"])
		}
		if m["returned"].(float64) != 2 {
			t.Errorf("returned = %v", m["returned"])
		}
		items, ok := m["items"].([]any)
		if !ok || len(items) != 2 {
			t.Fatalf("items = %v", m["items"])
		}
		first, ok := items[0].(map[string]any)
		if !ok {
			t.Fatalf("first item not a map: %T", items[0])
		}
		if first["id"] != "c1" {
			t.Errorf("first id = %v", first["id"])
		}
	})
}
