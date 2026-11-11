package tool

import (
	"strings"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetManagedAccountHandler_NoAuth(t *testing.T) {
	res, err := getManagedAccountHandler(testconn.CtxNoAuth(), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
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

func TestGetManagedAccountHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"account_id": "ma1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetManagedAccountHandler_MissingAccountID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: account_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetManagedAccountHandler_RedactsCheckoutSecret(t *testing.T) {
	conn := testconn.New(t)
	seen := false
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		seen = true
		account := managedAccountWithSecret()
		return &account, nil
	})

	res, err := getManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "ma1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !seen {
		t.Fatal("expected GET /secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id")
	}
	if strings.Contains(res.Content[0].Text, "s3cr3t") {
		t.Fatalf("checkout secret leaked: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "ma1" || m["username"] != "svc-sql" || m["state"] != "ok" {
		t.Errorf("account = %v", m)
	}
	checkout := m["checkouts"].([]any)[0].(map[string]any)
	if checkout["id"] != "c1" || checkout["username"] != "alice" {
		t.Errorf("checkout = %v", checkout)
	}
	if _, ok := checkout["secrets"]; ok {
		t.Errorf("checkouts[].secrets should be stripped: %v", checkout)
	}
}
