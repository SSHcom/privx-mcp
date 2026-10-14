package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func managedAccountWithSecret() secretsmanager.ManagedAccount {
	return secretsmanager.ManagedAccount{
		ID:               "ma1",
		Username:         "svc-sql",
		FullName:         "SQL Service",
		Email:            "svc@example.com",
		Enabled:          true,
		RotationEnabled:  true,
		ExplicitCheckout: true,
		State:            "ok",
		Comment:          "keep",
		PasswordPolicy:   &secretsmanager.PasswordPolicyHandle{ID: "pp1", Name: "default"},
		TargetDomain:     secretsmanager.TargetDomainHandle{ID: "td1", Name: "corp"},
		RotationHistory: []secretsmanager.SecretRotationEvent{{
			Version: 1,
			Trigger: "manual",
			Status:  "success",
		}},
		SecretCheckouts: []secretsmanager.SecretCheckout{{
			ID:               "c1",
			UserID:           "u1",
			Username:         "alice",
			ExplicitCheckout: true,
			Secrets: []secretsmanager.SecretVersion{{
				Version: 3,
				Secret:  "s3cr3t",
			}},
		}},
	}
}

func TestListManagedAccountsHandler_NoAuth(t *testing.T) {
	res, err := listManagedAccountsHandler(testconn.CtxNoAuth(), map[string]any{"id": "td1"})
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

func TestListManagedAccountsHandler_InvalidSortKey(t *testing.T) {
	conn := testconn.New(t)
	res, err := listManagedAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":      "td1",
		"sortKey": "created",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "sortKey must be id, username, full_name, or email") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListManagedAccountsHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := listManagedAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error result")
	}
	if !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListManagedAccountsHandler_RedactsCheckoutSecret(t *testing.T) {
	conn := testconn.New(t)
	seen := false
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts", func(body any) (any, error) {
		seen = true
		return response.ResultSet[secretsmanager.ManagedAccount]{
			Count: 1,
			Items: []secretsmanager.ManagedAccount{managedAccountWithSecret()},
		}, nil
	})

	res, err := listManagedAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":     "td1",
		"fields": "checkouts,rotation_history,target_domain",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !seen {
		t.Fatal("expected GET /secrets-manager/api/v1/targetdomains/:id/managedaccounts")
	}
	if strings.Contains(res.Content[0].Text, "s3cr3t") {
		t.Fatalf("checkout secret leaked: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	if m["limit"].(float64) != float64(common.TargetDomainsListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}
	items := m["items"].([]any)
	first := items[0].(map[string]any)
	if first["id"] != "ma1" || first["username"] != "svc-sql" || first["state"] != "ok" {
		t.Errorf("item = %v", first)
	}
	policy := first["password_policy"].(map[string]any)
	if policy["id"] != "pp1" || policy["name"] != "default" {
		t.Errorf("password_policy = %v", policy)
	}
	domain := first["target_domain"].(map[string]any)
	if domain["id"] != "td1" || domain["name"] != "corp" {
		t.Errorf("target_domain = %v", domain)
	}
	history := first["rotation_history"].([]any)
	event := history[0].(map[string]any)
	if event["status"] != "success" || event["trigger"] != "manual" {
		t.Errorf("rotation_history = %v", event)
	}
	checkouts := first["checkouts"].([]any)
	checkout := checkouts[0].(map[string]any)
	if checkout["id"] != "c1" || checkout["username"] != "alice" || checkout["user_id"] != "u1" {
		t.Errorf("checkout = %v", checkout)
	}
	if _, ok := checkout["secrets"]; ok {
		t.Errorf("checkouts[].secrets should be stripped: %v", checkout)
	}
}

func TestListManagedAccountsHandler_RawRedactsCheckoutSecret(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/targetdomains/:id/managedaccounts", func(body any) (any, error) {
		return response.ResultSet[secretsmanager.ManagedAccount]{
			Count: 1,
			Items: []secretsmanager.ManagedAccount{managedAccountWithSecret()},
		}, nil
	})

	res, err := listManagedAccountsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":  "td1",
		"raw": true,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if strings.Contains(res.Content[0].Text, "s3cr3t") {
		t.Fatalf("checkout secret leaked: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	first := m["items"].([]any)[0].(map[string]any)
	if first["username"] != "svc-sql" {
		t.Errorf("username = %v", first["username"])
	}
	checkout := first["checkouts"].([]any)[0].(map[string]any)
	if checkout["username"] != "alice" {
		t.Errorf("checkout = %v", checkout)
	}
	if _, ok := checkout["secrets"]; ok {
		t.Errorf("raw checkouts[].secrets should be stripped: %v", checkout)
	}
}
