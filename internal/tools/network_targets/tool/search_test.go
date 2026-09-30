package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestSearchNetworkTargetsHandler_InvalidSearchBody(t *testing.T) {
	conn := testconn.New(t)
	res, err := searchNetworkTargetsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": "not-an-object",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error for non-object search")
	}
	if !strings.Contains(res.Content[0].Text, "invalid search body") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestSearchNetworkTargetsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/network-access-manager/api/v1/nwtargets/search", func(body any) (any, error) {
		return response.ResultSet[networkaccessmanager.NetworkTarget]{
			Count: 1,
			Items: []networkaccessmanager.NetworkTarget{{ID: "nt1", Name: "t1"}},
		}, nil
	})

	res, err := searchNetworkTargetsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": map[string]any{"keywords": "t1"},
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
	if m["nextOffset"] != nil {
		t.Errorf("nextOffset = %v, want null on last page", m["nextOffset"])
	}
}

func TestBuildNetworkTargetSearch(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		s, err := buildNetworkTargetSearch(nil)
		if err != nil || s == nil {
			t.Fatalf("got %v, err %v", s, err)
		}
	})
	t.Run("not object", func(t *testing.T) {
		_, err := buildNetworkTargetSearch([]any{"x"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
