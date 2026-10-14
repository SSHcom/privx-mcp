package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

const rotatePath = "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id/rotate"

func TestRotateManagedAccountHandler_EmptyBody(t *testing.T) {
	conn := testconn.New(t)
	called := false
	conn.Handle("POST", rotatePath, func(body any) (any, error) {
		called = true
		if body != nil {
			t.Errorf("body = %#v, want nil", body)
		}
		return nil, nil
	})

	res, err := rotateManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !called {
		t.Fatal("expected POST " + rotatePath)
	}
	if strings.Contains(res.Content[0].Text, "password") || strings.Contains(res.Content[0].Text, "secret") {
		t.Fatalf("result included a password field: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "ma1" || m["rotation_started"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestRotateManagedAccountHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := rotateManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"account_id": "ma1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestRotateManagedAccountHandler_MissingAccountID(t *testing.T) {
	conn := testconn.New(t)
	res, err := rotateManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: account_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
