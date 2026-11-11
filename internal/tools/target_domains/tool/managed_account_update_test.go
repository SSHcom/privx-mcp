package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestUpdateManagedAccountHandler_OverlaysFlags(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		return managedAccountWithSecret(), nil
	})
	conn.Handle("PUT", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/:account_id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var account secretsmanager.ManagedAccount
		if err := json.Unmarshal(raw, &account); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if account.Comment != "edited" {
			t.Errorf("comment = %q, want edited", account.Comment)
		}
		if account.Username != "svc-sql" {
			t.Errorf("username = %q, want svc-sql", account.Username)
		}
		if account.ExplicitCheckout {
			t.Error("explicit_checkout stayed true")
		}
		if !account.RotationEnabled {
			t.Error("omitted rotation_enabled was cleared")
		}
		return nil, nil
	})

	res, err := updateManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":                "td1",
		"account_id":        "ma1",
		"comment":           "edited",
		"username":          "renamed",
		"explicit_checkout": false,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "s3cr3t") {
		t.Fatalf("result echoed a checkout secret: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "ma1" || m["updated"] != true {
		t.Errorf("result = %v", m)
	}
	if _, ok := m["checkouts"]; ok {
		t.Error("result included checkouts")
	}
}

func TestUpdateManagedAccountHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := updateManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"account_id": "ma1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateManagedAccountHandler_MissingAccountID(t *testing.T) {
	conn := testconn.New(t)
	res, err := updateManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: account_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
