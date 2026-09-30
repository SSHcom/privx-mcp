package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestMonitorServiceStatusHandler_NoAuth(t *testing.T) {
	res, err := monitorServiceStatusHandler(testconn.CtxNoAuth(), map[string]any{})
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

func TestMonitorServiceStatusHandler_AsIs(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/monitor-service/api/v1/status", func(body any) (any, error) {
		return response.ServiceStatus{
			Version:       "43.0-72",
			Status:        "RUNNING",
			StatusMessage: "ok",
			APIVersion:    "v1",
		}, nil
	})

	res, err := monitorServiceStatusHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["status"] != "RUNNING" || m["version"] != "43.0-72" {
		t.Errorf("got %v", m)
	}
	if m["status_message"] != "ok" || m["api_version"] != "v1" {
		t.Errorf("expected full status object, got %v", m)
	}
}
