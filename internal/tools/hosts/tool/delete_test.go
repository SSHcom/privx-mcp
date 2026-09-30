package tool

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeleteHostHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1"}, nil
	})
	conn.Handle("POST", "/connection-manager/api/v1/connections/search", func(body any) (any, error) {
		// No connections in the window.
		return response.ResultSet[connItem]{Items: nil}, nil
	})
	conn.Handle("DELETE", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "h1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["deleted"] != true {
		t.Errorf("deleted = %v, want true", m["deleted"])
	}
}

func TestDeleteHostHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteHostHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteHostHandler_HostMissing(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := deleteHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch host") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteHostHandler_ActiveConnectionBlocks(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1"}, nil
	})
	conn.Handle("POST", "/connection-manager/api/v1/connections/search", func(body any) (any, error) {
		// An active connection started 1h ago, not disconnected.
		return response.ResultSet[connItem]{
			Items: []connItem{{
				ID:           "c1",
				Connected:    time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
				Disconnected: "",
			}},
		}, nil
	})
	res, err := deleteHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error for active connection")
	}
	if !strings.Contains(res.Content[0].Text, "refusing to delete") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteHostHandler_ClosedConnectionDoesNotBlock(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1"}, nil
	})
	conn.Handle("POST", "/connection-manager/api/v1/connections/search", func(body any) (any, error) {
		return response.ResultSet[connItem]{
			Items: []connItem{{
				ID:           "c1",
				Connected:    time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339),
				Disconnected: time.Now().UTC().Format(time.RFC3339),
			}},
		}, nil
	})
	conn.Handle("DELETE", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestDeleteHostHandler_DeleteFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return hoststore.Host{ID: "h1"}, nil
	})
	conn.Handle("POST", "/connection-manager/api/v1/connections/search", func(body any) (any, error) {
		return response.ResultSet[connItem]{}, nil
	})
	conn.Handle("DELETE", "/host-store/api/v1/hosts/:id", func(body any) (any, error) {
		return nil, errors.New("delete failed")
	})
	res, err := deleteHostHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "h1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to delete host") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
