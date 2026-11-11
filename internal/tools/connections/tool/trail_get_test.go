package tool

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/connectionmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

// stdinLine builds a base64-encoded stdin trail-log event line.
func stdinLine(ts, text string) string {
	ev := map[string]any{
		"type": "stdin",
		"ts":   ts,
		"data": base64.StdEncoding.EncodeToString([]byte(text)),
	}
	b, _ := json.Marshal(ev)

	return string(b)
}

func execLine(ts, cmd string) string {
	ev := map[string]any{"type": "exec", "ts": ts, "command": cmd}
	b, _ := json.Marshal(ev)

	return string(b)
}

// setupTrail registers the connection (typed + raw), the trail-log session, and
// the trail-log fetch for a single shell channel "ch1".
func setupTrail(t *testing.T, conn *testconn.FakeConnector, c connectionmanager.Connection, logLines []string) {
	t.Helper()

	conn.Handle("GET", "/connection-manager/api/v1/connections/:id", func(any) (any, error) {
		return c, nil
	})

	rawConn := map[string]any{
		"id":            c.ID,
		"type":          c.Type,
		"audit_enabled": c.AuditEnabled,
		"trail": map[string]any{
			"connection_id": c.ID,
			"channels": []map[string]any{
				{
					"id":            "ch1",
					"type":          "shell",
					"protocol_file": map[string]any{"status": "OK"},
				},
			},
		},
	}
	conn.HandleFetch("/connection-manager/api/v1/connections/:id", func() ([]byte, error) {
		return json.Marshal(rawConn)
	})

	conn.Handle("POST", "/connection-manager/api/v1/connections/:id/channel/:chan/log", func(any) (any, error) {
		return connectionmanager.DownloadSessionID{SessionID: "sess1"}, nil
	})

	conn.HandleFetch("/connection-manager/api/v1/connections/:id/channel/:chan/log/:sess", func() ([]byte, error) {
		return []byte(strings.Join(logLines, "\n")), nil
	})
}

func TestTrailGetHandler_NoAuth(t *testing.T) {
	res, err := trailGetHandler(testconn.CtxNoAuth(), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "authentication error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestTrailGetHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestTrailGetHandler_NotSSH(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/connection-manager/api/v1/connections/:id", func(any) (any, error) {
		return connectionmanager.Connection{ID: "c1", Type: "RDP", AuditEnabled: true}, nil
	})

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "requires an SSH connection") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestTrailGetHandler_AuditDisabled(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/connection-manager/api/v1/connections/:id", func(any) (any, error) {
		return connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: false}, nil
	})

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "session recording") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestTrailGetHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	setupTrail(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", Status: "DISCONNECTED", AuditEnabled: true, TrailID: "t1"},
		[]string{
			stdinLine("2026-01-01T00:00:01.5Z", "uptime\r"),
			execLine("2026-01-01T00:00:02.0Z", "whoami"),
			stdinLine("2026-01-01T00:00:03.0Z", "ls -la\r"),
		},
	)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)

	if m["count"].(float64) != 3 {
		t.Errorf("count = %v", m["count"])
	}
	if m["limit"].(float64) != float64(common.ConnectionTrailListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}

	items, ok := m["items"].([]any)
	if !ok || len(items) != 3 {
		t.Fatalf("items = %v", m["items"])
	}

	got := make([]string, 0, len(items))
	for _, it := range items {
		cmd := it.(map[string]any)
		got = append(got, cmd["command"].(string))
	}
	want := []string{"uptime", "whoami", "ls -la"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	first := items[0].(map[string]any)
	if first["channel_id"] != "ch1" {
		t.Errorf("channel_id = %v", first["channel_id"])
	}
	if first["timestamp"] != "2026-01-01T00:00:01" {
		t.Errorf("timestamp = %v", first["timestamp"])
	}
}

func TestTrailGetHandler_Keywords(t *testing.T) {
	conn := testconn.New(t)
	setupTrail(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: true},
		[]string{
			stdinLine("2026-01-01T00:00:01Z", "uptime\r"),
			stdinLine("2026-01-01T00:00:02Z", "ls -la\r"),
		},
	)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1", "keywords": "ls"})
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
	items := m["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["command"] != "ls -la" {
		t.Fatalf("items = %v", items)
	}
}

func TestTrailGetHandler_RawIncludesConnectionMeta(t *testing.T) {
	conn := testconn.New(t)
	setupTrail(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: true, TrailID: "t1", SessionID: "s1"},
		[]string{stdinLine("2026-01-01T00:00:01Z", "uptime\r")},
	)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1", "raw": true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	connMeta, ok := m["connection"].(map[string]any)
	if !ok {
		t.Fatalf("connection meta missing: %v", m["connection"])
	}
	if connMeta["trail_id"] != "t1" || connMeta["session_id"] != "s1" {
		t.Errorf("connection meta = %v", connMeta)
	}
}
