package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestGetUserHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id", func(body any) (any, error) {
		return rolestore.User{ID: "u1", Principal: "alice", Email: "alice@example.com"}, nil
	})
	res, err := getUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "u1" {
		t.Errorf("id = %v", m["id"])
	}
	if m["principal"] != "alice" {
		t.Errorf("principal = %v", m["principal"])
	}
}

func TestGetUserHandler_RedactsSensitiveFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id", func(body any) (any, error) {
		return rolestore.User{
			ID:                  "u1",
			Principal:           "alice",
			Password:            "secret",
			Settings:            json.RawMessage(`{"theme":"dark"}`),
			AuthorizedKeys:      []rolestore.AuthorizedKey{{ID: "k1"}},
			WebAuthnCredentials: []rolestore.Credential{{ID: "c1"}},
			Roles: []rolestore.Role{{
				ID:                  "r1",
				Name:                "admin",
				PrincipalPublicKeys: []string{"ssh-ed25519 AAAA"},
			}},
		}, nil
	})
	res, err := getUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	for _, field := range []string{
		"password",
		"settings",
		"authorized_keys",
		"webauthn_credentials",
	} {
		if _, ok := m[field]; ok {
			t.Errorf("field %q should be redacted", field)
		}
	}
	if m["principal"] != "alice" {
		t.Errorf("principal should remain, got %v", m["principal"])
	}
	role := m["roles"].([]any)[0].(map[string]any)
	if _, ok := role["principal_public_key_strings"]; ok {
		t.Error("principal_public_key_strings should be redacted from roles")
	}
}

func TestGetUserHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := getUserHandler(testconn.CtxWithAuth(conn), map[string]any{})
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

func TestGetUserHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/users/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := getUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.Content[0].Text, "failed to fetch user") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
