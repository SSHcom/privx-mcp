package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

const deleteManagedAccountPath = "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id"

func TestDeleteManagedAccountHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	called := false
	conn.Handle("DELETE", deleteManagedAccountPath, func(body any) (any, error) {
		called = true
		if body != nil {
			t.Errorf("body = %#v, want nil", body)
		}
		return nil, nil
	})

	res, err := deleteManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !called {
		t.Fatal("expected DELETE " + deleteManagedAccountPath)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "acc1" || m["deleted"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestDeleteManagedAccountHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"account_id": "acc1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteManagedAccountHandler_MissingAccountID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: account_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteManagedAccountHandler_NoAuth(t *testing.T) {
	res, err := deleteManagedAccountHandler(testconn.CtxNoAuth(), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "authentication error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteManagedAccountHandler_APIError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("DELETE", deleteManagedAccountPath, func(body any) (any, error) {
		return nil, errors.New("privx rejected")
	})

	res, err := deleteManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to delete managed account") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
