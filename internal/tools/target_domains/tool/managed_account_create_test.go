package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

const createManagedAccountPath = "/secrets-manager/api/v1/targetdomains/:id/managedaccounts/batch/create"

func TestCreateManagedAccountHandler_FromScannedAccount(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", createManagedAccountPath, func(body any) (any, error) {
		batch := decodeCreateBatch(t, body)
		if len(batch.IDs) != 1 || batch.IDs[0] != "acc1" {
			t.Errorf("ids = %#v, want [acc1]", batch.IDs)
		}
		if !batch.Data.Enabled || batch.Data.RotationEnabled || batch.Data.Rotate || batch.Data.ExplicitCheckout || batch.Data.DisableRDPCertAuth {
			t.Errorf("flags = %+v", batch.Data)
		}
		if batch.Data.PasswordPolicy.ID != "pol1" {
			t.Errorf("password policy = %q, want pol1", batch.Data.PasswordPolicy.ID)
		}
		if batch.Data.Comment != "" {
			t.Errorf("comment = %q, want empty", batch.Data.Comment)
		}
		return secretsmanager.IDList{IDs: []string{"acc1"}}, nil
	})

	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":                    "td1",
		"account_id":            "acc1",
		"enabled":               true,
		"rotation_enabled":      false,
		"rotate":                false,
		"explicit_checkout":     false,
		"disable_rdp_cert_auth": false,
		"password_policy_id":    "pol1",
		"comment":               "",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "acc1" || m["created"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestCreateManagedAccountHandler_DefaultsEnabled(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", createManagedAccountPath, func(body any) (any, error) {
		batch := decodeCreateBatch(t, body)
		if !batch.Data.Enabled {
			t.Error("omitted enabled defaulted to false")
		}
		if batch.Data.RotationEnabled || batch.Data.Rotate || batch.Data.PasswordPolicy.ID != "" || batch.Data.Comment != "" {
			t.Errorf("data = %+v", batch.Data)
		}
		return secretsmanager.IDList{}, nil
	})

	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "acc1" || m["created"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestCreateManagedAccountHandler_EnabledFalse(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", createManagedAccountPath, func(body any) (any, error) {
		batch := decodeCreateBatch(t, body)
		if batch.Data.Enabled {
			t.Error("enabled stayed true")
		}
		return secretsmanager.IDList{IDs: []string{"acc1"}}, nil
	})

	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
		"enabled":    false,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
}

func TestCreateManagedAccountHandler_RotationRequiresPolicy(t *testing.T) {
	conn := testconn.New(t)
	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":               "td1",
		"account_id":       "acc1",
		"rotation_enabled": true,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "password_policy_id is required") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateManagedAccountHandler_RotateRequiresPolicy(t *testing.T) {
	conn := testconn.New(t)
	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
		"rotate":     true,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "password_policy_id is required") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateManagedAccountHandler_InvalidBool(t *testing.T) {
	conn := testconn.New(t)
	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
		"enabled":    "yes",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "enabled must be a boolean") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateManagedAccountHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"account_id": "acc1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateManagedAccountHandler_MissingAccountID(t *testing.T) {
	conn := testconn.New(t)
	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "td1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: account_id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateManagedAccountHandler_NoAuth(t *testing.T) {
	res, err := createManagedAccountHandler(testconn.CtxNoAuth(), map[string]any{
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

func TestCreateManagedAccountHandler_APIError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", createManagedAccountPath, func(body any) (any, error) {
		return nil, errors.New("privx rejected")
	})

	res, err := createManagedAccountHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":         "td1",
		"account_id": "acc1",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to create managed account") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func decodeCreateBatch(t *testing.T, body any) secretsmanager.ManagedAccountCreateBatch {
	t.Helper()

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var batch secretsmanager.ManagedAccountCreateBatch
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	return batch
}
