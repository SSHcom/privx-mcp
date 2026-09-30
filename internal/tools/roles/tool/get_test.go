package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetRoleHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{
			ID:                  "r1",
			Name:                "admin",
			Comment:             "admins",
			PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
			Context:             rolestore.ContextualLimit{Enabled: true, IPMasks: []string{"10.0.0.0/8"}},
		}, nil
	})
	res, err := getRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "r1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["name"] != "admin" {
		t.Errorf("name = %v", m["name"])
	}
	if _, ok := m["principal_public_key_strings"]; ok {
		t.Error("principal_public_key_strings should be redacted")
	}
	context := m["context"].(map[string]any)
	if _, ok := context["ip_masks"]; ok {
		t.Error("context.ip_masks should be redacted")
	}
	if context["enabled"] != true {
		t.Errorf("enabled = %v", context["enabled"])
	}
}

func TestGetRoleHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getRoleHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestGetRoleHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := getRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
