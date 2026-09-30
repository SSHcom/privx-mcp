package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/monitor"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestSearchAuditEventsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	var capturedBody map[string]any
	conn.Handle("POST", "/monitor-service/api/v1/auditevents/search", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		if err := json.Unmarshal(raw, &capturedBody); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		return response.ResultSet[monitor.AuditEvent]{
			Count: 1,
			Items: []monitor.AuditEvent{
				{EventID: "1001", EventName: "LOGIN", ServiceName: "auth"},
			},
		}, nil
	})

	res, err := searchAuditEventsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": map[string]any{"keywords": "login"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	if capturedBody == nil {
		t.Fatal("expected POST body to be captured")
	}
	if capturedBody["keywords"] != "login" {
		t.Errorf("search.keywords = %v, want login", capturedBody["keywords"])
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	if m["returned"].(float64) != 1 {
		t.Errorf("returned = %v", m["returned"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
}

func TestSearchAuditEventsHandler_InvalidSearchBody(t *testing.T) {
	conn := testconn.New(t)
	res, err := searchAuditEventsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": []any{"not-an-object"},
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

func TestBuildAuditEventSearch(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		s, err := buildAuditEventSearch(nil)
		if err != nil || s == nil {
			t.Fatalf("got %v, err %v", s, err)
		}
	})
	t.Run("not object", func(t *testing.T) {
		_, err := buildAuditEventSearch("x")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "search must be an object" {
			t.Errorf("err = %q", err.Error())
		}
	})
}
