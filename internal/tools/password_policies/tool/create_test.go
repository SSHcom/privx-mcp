package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreatePasswordPolicyHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/secrets-manager/api/v1/password-policy", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var p secretsmanager.PasswordPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("unmarshal policy: %v", err)
		}
		if p.Name != "my-policy" {
			t.Errorf("name = %q, want my-policy", p.Name)
		}
		if p.MaxVersions != 3 {
			t.Errorf("max_versions = %d, want 3", p.MaxVersions)
		}
		return response.Identifier{ID: "new-pp"}, nil
	})

	res, err := createHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name":         "my-policy",
		"max_versions": float64(3),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-pp" {
		t.Errorf("id = %v, want new-pp", m["id"])
	}
}

func TestCreatePasswordPolicyHandler_MissingName(t *testing.T) {
	conn := testconn.New(t)
	res, err := createHandler(testconn.CtxWithAuth(conn), map[string]any{
		"max_versions": float64(3),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
