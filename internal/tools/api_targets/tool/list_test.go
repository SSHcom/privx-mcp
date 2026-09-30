package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/apiproxy"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestListAPITargetsHandler_NoAuth(t *testing.T) {
	res, err := listAPITargetsHandler(testconn.CtxNoAuth(), map[string]any{})
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

func TestListAPITargetsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/api-proxy/api/v1/api-targets", func(body any) (any, error) {
		return response.ResultSet[apiproxy.ApiTarget]{
			Count: 2,
			Items: []apiproxy.ApiTarget{
				{ID: "at1", Name: "payments"},
				{ID: "at2", Name: "billing"},
			},
		}, nil
	})

	res, err := listAPITargetsHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
	if m["returned"].(float64) != 2 {
		t.Errorf("returned = %v", m["returned"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %v", m["items"])
	}
}
