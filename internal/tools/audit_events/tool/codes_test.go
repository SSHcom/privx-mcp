package tool

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetAuditEventCodesHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/auditevents/codes", func(body any) (any, error) {
		return monitor.AuditEventCodes{
			1001: {EventID: 1001, EventName: "LOGIN", EventDesc: "User login"},
			1002: {EventID: 1002, EventName: "LOGOUT", EventDesc: "User logout"},
		}, nil
	})

	res, err := auditEventCodesHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if len(m) != 2 {
		t.Fatalf("expected 2 codes, got %d (%v)", len(m), m)
	}
	code, ok := m["1001"].(map[string]any)
	if !ok {
		t.Fatalf("code 1001 = %v", m["1001"])
	}
	if code["event_name"] != "LOGIN" {
		t.Errorf("event_name = %v", code["event_name"])
	}
	if code["event_desc"] != "User login" {
		t.Errorf("event_desc = %v", code["event_desc"])
	}
}
