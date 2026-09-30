package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetPasswordPolicyHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/password-policy/:id", func(body any) (any, error) {
		return secretsmanager.PasswordPolicy{ID: "pp1", Name: "policy-one"}, nil
	})
	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "pp1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "pp1" {
		t.Errorf("id = %v, want pp1", m["id"])
	}
}

func TestGetPasswordPolicyHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
