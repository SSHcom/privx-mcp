package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetNetworkTargetHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/network-access-manager/api/v1/nwtargets/:id", func(body any) (any, error) {
		return networkaccessmanager.NetworkTarget{ID: "nt1", Name: "t1"}, nil
	})
	res, err := getNetworkTargetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "nt1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "nt1" {
		t.Errorf("id = %v", m["id"])
	}
}

func TestGetNetworkTargetHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getNetworkTargetHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
