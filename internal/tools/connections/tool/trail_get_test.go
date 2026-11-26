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

	setupTrailChannels(t, conn, c, []map[string]any{
		{
			"id":            "ch1",
			"type":          "shell",
			"protocol_file": map[string]any{"status": "OK"},
		},
	}, logLines)
}

// setupTrailChannels is setupTrail with caller-supplied raw trail channels. The
// fake returns the same log for every channel, so tests that care about
// commands should use a single channel.
func setupTrailChannels(t *testing.T, conn *testconn.FakeConnector, c connectionmanager.Connection, channels []map[string]any, logLines []string) {
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
			"channels":      channels,
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

// shellAndSFTPChannels mirrors a real PrivX trail: a shell channel and an sftp
// channel that uploaded one file (direction 2 = client to server).
func shellAndSFTPChannels() []map[string]any {
	return []map[string]any{
		{
			"id":   "0",
			"type": "shell",
			"protocol_file": map[string]any{
				"id": "p0", "direction": 3, "status": "OK", "closed": true,
				"open_time":  "2026-11-25T08:53:54.681658511Z",
				"close_time": "2026-11-25T08:54:11.613634716Z",
			},
			"bytes_client_to_server": 373,
			"bytes_server_to_client": 1110,
		},
		{
			"id":   "1",
			"type": "sftp",
			"protocol_file": map[string]any{
				"id": "p1", "direction": 3, "status": "OK", "closed": true,
				"open_time":  "2026-11-25T08:54:05.712132474Z",
				"close_time": "2026-11-25T08:54:14.326616062Z",
			},
			"transferred_files": []map[string]any{
				{
					"id":           "f1",
					"name":         "/home/rocky/privx-0.1.0-2026-11-13.spl",
					"direction":    2,
					"open_time":    "2026-11-25T08:54:08.627028823Z",
					"close_time":   "2026-11-25T08:54:08.686443525Z",
					"payload_size": 2096,
					"closed":       true,
					"status":       "OK",
				},
			},
			"bytes_client_to_server": 47,
		},
	}
}

func TestTrailGetHandler_ReportsTransferredFiles(t *testing.T) {
	conn := testconn.New(t)
	// No log lines: the sftp channel yields no commands, which is the case that
	// used to hide the transfer entirely.
	setupTrailChannels(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: true},
		shellAndSFTPChannels(), nil)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)

	if m["count"].(float64) != 0 {
		t.Errorf("count = %v, want 0 commands", m["count"])
	}

	if m["transferred_files_total"].(float64) != 1 {
		t.Errorf("transferred_files_total = %v", m["transferred_files_total"])
	}

	files := m["transferred_files"].([]any)
	if len(files) != 1 {
		t.Fatalf("transferred_files = %v", files)
	}

	f := files[0].(map[string]any)
	if f["name"] != "/home/rocky/privx-0.1.0-2026-11-13.spl" {
		t.Errorf("name = %v", f["name"])
	}
	if f["direction"] != "upload" {
		t.Errorf("direction = %v, want upload (PrivX direction 2 = client to server)", f["direction"])
	}
	if f["size_bytes"].(float64) != 2096 || f["status"] != "OK" || f["channel_type"] != "sftp" {
		t.Errorf("file = %v", f)
	}

	channels := m["channels"].([]any)
	if len(channels) != 2 {
		t.Fatalf("channels = %v", channels)
	}

	shell, sftp := channels[0].(map[string]any), channels[1].(map[string]any)
	if shell["type"] != "shell" || shell["transferred_files"].(float64) != 0 {
		t.Errorf("shell channel = %v", shell)
	}
	if sftp["type"] != "sftp" || sftp["transferred_files"].(float64) != 1 {
		t.Errorf("sftp channel = %v", sftp)
	}
	if sftp["bytes_client_to_server"].(float64) != 47 {
		t.Errorf("sftp bytes_client_to_server = %v", sftp["bytes_client_to_server"])
	}
}

func TestTrailGetHandler_NoTransfersReportsEmptyList(t *testing.T) {
	conn := testconn.New(t)
	setupTrail(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: true},
		[]string{stdinLine("2026-01-01T00:00:01Z", "uptime\r")},
	)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)

	files, ok := m["transferred_files"].([]any)
	if !ok || len(files) != 0 {
		t.Fatalf("transferred_files = %v, want an explicit empty list", m["transferred_files"])
	}

	if m["transferred_files_total"].(float64) != 0 {
		t.Errorf("transferred_files_total = %v", m["transferred_files_total"])
	}
}

func TestTrailGetHandler_ChannelFilterLimitsTransfers(t *testing.T) {
	conn := testconn.New(t)
	setupTrailChannels(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: true},
		shellAndSFTPChannels(), nil)

	// Asking for the shell channel only must not report the sftp upload.
	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1", "channel_id": "0"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)

	if m["transferred_files_total"].(float64) != 0 {
		t.Errorf("transferred_files_total = %v, want 0 for the shell channel", m["transferred_files_total"])
	}

	if channels := m["channels"].([]any); len(channels) != 1 {
		t.Errorf("channels = %v, want only the shell channel", channels)
	}
}

func TestTrailGetHandler_KeywordsDoNotHideTransfers(t *testing.T) {
	conn := testconn.New(t)
	setupTrailChannels(t, conn,
		connectionmanager.Connection{ID: "c1", Type: "SSH", AuditEnabled: true},
		shellAndSFTPChannels(), nil)

	res, err := trailGetHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "c1", "keywords": "nomatch"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)

	if m["transferred_files_total"].(float64) != 1 {
		t.Errorf("a command keyword must not hide transferred files, total = %v", m["transferred_files_total"])
	}
}
