package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestListNetworkTargetsHandler_NoAuth(t *testing.T) {
	res, err := listNetworkTargetsHandler(testconn.CtxNoAuth(), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "authentication error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListNetworkTargetsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/network-access-manager/api/v1/nwtargets", func(body any) (any, error) {
		return response.ResultSet[networkaccessmanager.NetworkTarget]{
			Count: 2,
			Items: []networkaccessmanager.NetworkTarget{
				{ID: "nt1", Name: "t1"},
				{ID: "nt2", Name: "t2"},
			},
		}, nil
	})

	res, err := listNetworkTargetsHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
	if m["limit"].(float64) != float64(common.NetworkTargetsListLimit) {
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
	if first["id"] != "nt1" {
		t.Errorf("first id = %v", first["id"])
	}
	if first["name"] != "t1" {
		t.Errorf("first name = %v", first["name"])
	}
}
