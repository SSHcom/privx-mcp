package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func sampleComponent() map[string]any {
	return map[string]any{
		"component_name": "API-PROXY",
		"component_type": "MICROSERVICE",
		"hostname":       "host-a",
		"status_uri":     "https://localhost/api-proxy/api/v1/status",
		"status": map[string]any{
			"version":    "43.0-72",
			"status":     "RUNNING",
			"start_time": "2026-08-07T20:00:07Z",
			"zdu":        map[string]any{"phase": "idle"},
		},
		"created": "2026-08-20T10:20:02Z",
	}
}

func TestComponentsStatusHandler_NoAuth(t *testing.T) {
	res, err := componentsStatusHandler(testconn.CtxNoAuth(), map[string]any{})
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

func TestComponentsStatusHandler_DefaultProjection(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/components", func(body any) (any, error) {
		return map[string]any{
			"host-a": []any{sampleComponent()},
		}, nil
	})

	res, err := componentsStatusHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	items, ok := m["host-a"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("host-a = %v", m["host-a"])
	}
	item := items[0].(map[string]any)
	if item["component_name"] != "API-PROXY" {
		t.Errorf("component_name = %v", item["component_name"])
	}
	if _, ok := item["status_uri"]; ok {
		t.Error("status_uri should be dropped")
	}
	st := item["status"].(map[string]any)
	if st["status"] != "RUNNING" {
		t.Errorf("status.status = %v", st["status"])
	}
	if _, ok := st["zdu"]; ok {
		t.Error("zdu should be dropped")
	}
}

func TestComponentsStatusHandler_Raw(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/components", func(body any) (any, error) {
		return map[string]any{
			"host-a": []any{sampleComponent()},
		}, nil
	})

	res, err := componentsStatusHandler(testconn.CtxWithAuth(conn), map[string]any{"raw": true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	item := m["host-a"].([]any)[0].(map[string]any)
	st := item["status"].(map[string]any)
	if _, ok := st["zdu"]; !ok {
		t.Error("raw should keep zdu")
	}
}

func TestComponentsStatusHandler_Hostname(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/components/:hostname", func(body any) (any, error) {
		return []any{sampleComponent()}, nil
	})

	res, err := componentsStatusHandler(testconn.CtxWithAuth(conn), map[string]any{"hostname": "host-a"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	items, ok := m["host-a"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected wrap under host-a, got %v", m)
	}
	item := items[0].(map[string]any)
	if item["component_name"] != "API-PROXY" {
		t.Errorf("item = %v", item)
	}
}
