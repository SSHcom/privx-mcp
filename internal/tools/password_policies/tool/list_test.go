package tool

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestListPasswordPoliciesHandler_NoAuth(t *testing.T) {
	res, err := listHandler(testconn.CtxNoAuth(), map[string]any{})
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

func TestListPasswordPoliciesHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/secrets-manager/api/v1/password-policies", func(body any) (any, error) {
		return response.ResultSet[secretsmanager.PasswordPolicy]{
			Count: 2,
			Items: []secretsmanager.PasswordPolicy{
				{ID: "pp1", Name: "policy-one"},
				{ID: "pp2", Name: "policy-two"},
			},
		}, nil
	})

	res, err := listHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 2 {
		t.Errorf("count = %v", m["count"])
	}
	if m["returned"].(float64) != 2 {
		t.Errorf("returned = %v", m["returned"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %v", m["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("first item not a map: %T", items[0])
	}
	if first["id"] != "pp1" {
		t.Errorf("first id = %v", first["id"])
	}
}
