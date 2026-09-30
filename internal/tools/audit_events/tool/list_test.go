package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestListAuditEventsHandler_NoAuth(t *testing.T) {
	res, err := listAuditEventsHandler(testconn.CtxNoAuth(), map[string]any{})
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

func TestListAuditEventsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/auditevents", func(body any) (any, error) {
		return response.ResultSet[monitor.AuditEvent]{
			Count: 2,
			Items: []monitor.AuditEvent{
				{EventID: "1001", EventName: "LOGIN", ServiceName: "auth"},
				{EventID: "1002", EventName: "LOGOUT", ServiceName: "auth"},
			},
		}, nil
	})

	res, err := listAuditEventsHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
