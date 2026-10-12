package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

// scanPath is POST /secrets-manager/api/v1/targetdomains/{id}/refresh.
// RefreshTargetDomain is the account scan. /scan 404s on this PrivX.
const scanPath = "/secrets-manager/api/v1/targetdomains/:id/refresh"

func TestScanTargetDomainHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	called := false
	conn.Handle("POST", scanPath, func(body any) (any, error) {
		called = true
		if body != nil {
			t.Errorf("body = %#v, want nil", body)
		}
		return nil, nil
	})
	res, err := scanTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !called {
		t.Fatal("expected POST " + scanPath)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "td1" {
		t.Errorf("id = %v, want td1", m["id"])
	}
	if m["scan_started"] != true {
		t.Errorf("scan_started = %v, want true", m["scan_started"])
	}
}

func TestScanTargetDomainHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := scanTargetDomainHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
