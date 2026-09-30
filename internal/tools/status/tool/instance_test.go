package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestInstanceStatusHandler_NoAuth(t *testing.T) {
	res, err := instanceStatusHandler(testconn.CtxNoAuth(), map[string]any{})
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

func TestInstanceStatusHandler_DefaultNestedStatus(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/instance/status", func(body any) (any, error) {
		return []any{
			map[string]any{
				"component_name": "API-PROXY",
				"component_type": "MICROSERVICE",
				"hostname":       "host-a",
				"status_uri":     "https://localhost/api-proxy/api/v1/status",
				"status": map[string]any{
					"status":     "RUNNING",
					"start_time": "2026-08-07T20:00:07Z",
					"version":    "43.0-72",
					"zdu":        map[string]any{"phase": "idle"},
				},
			},
		}, nil
	})

	res, err := instanceStatusHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	items := testconn.DecodeResultAny(t, res.Content[0].Text).([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	item := items[0].(map[string]any)
	if item["component_name"] != "API-PROXY" {
		t.Errorf("component_name = %v", item["component_name"])
	}
	if _, ok := item["hostname"]; ok {
		t.Error("hostname should be dropped by defaults")
	}
	if _, ok := item["status_uri"]; ok {
		t.Error("status_uri should be dropped by defaults")
	}
	st := item["status"].(map[string]any)
	if st["status"] != "RUNNING" {
		t.Errorf("status.status = %v", st["status"])
	}
	if _, ok := st["zdu"]; ok {
		t.Error("zdu should be dropped")
	}
}

func TestInstanceStatusHandler_Raw(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/instance/status", func(body any) (any, error) {
		return []any{
			map[string]any{
				"component_name": "API-PROXY",
				"status": map[string]any{
					"status": "RUNNING",
					"zdu":    map[string]any{"phase": "idle"},
				},
			},
		}, nil
	})

	res, err := instanceStatusHandler(testconn.CtxWithAuth(conn), map[string]any{"raw": true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	items := testconn.DecodeResultAny(t, res.Content[0].Text).([]any)
	st := items[0].(map[string]any)["status"].(map[string]any)
	if _, ok := st["zdu"]; !ok {
		t.Error("raw should keep zdu")
	}
}
