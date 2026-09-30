package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestCreateLocalUserHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	var sentPassword string
	conn.Handle("POST", "/local-user-store/api/v1/users", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var u userstore.LocalUser
		if err := json.Unmarshal(raw, &u); err != nil {
			t.Fatalf("unmarshal user: %v", err)
		}
		if u.Principal != "alice" {
			t.Errorf("username = %q, want alice", u.Principal)
		}
		if u.FullName != "Alice Example" {
			t.Errorf("full_name = %q", u.FullName)
		}
		if u.Email != "alice@example.com" {
			t.Errorf("email = %q", u.Email)
		}
		if u.Password.Password == "" {
			t.Error("password is empty, want random generated password")
		}
		if u.Password.Password == "password" {
			t.Error("password must not be the old hardcoded value")
		}
		if !u.PasswordChangeRequired {
			t.Error("password_change_required = false, want true")
		}
		sentPassword = u.Password.Password
		return response.Identifier{ID: "new-user-id"}, nil
	})

	res, err := createLocalUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"username":  "alice",
		"full_name": "Alice Example",
		"email":     "alice@example.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "new-user-id" {
		t.Errorf("id = %v, want new-user-id", m["id"])
	}
	if _, has := m["password"]; has {
		t.Error("password must not be returned in the response")
	}
	if sentPassword == "" {
		t.Error("handler did not send a generated password to PrivX")
	}
}

func TestGenerateRandomPassword(t *testing.T) {
	a, err := generateRandomPassword()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := generateRandomPassword()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if a == "" || b == "" {
		t.Fatal("empty password")
	}
	if a == b {
		t.Error("consecutive passwords should differ")
	}
}

func TestCreateLocalUserHandler_MissingUsername(t *testing.T) {
	conn := testconn.New(t)
	res, err := createLocalUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"full_name": "Alice Example",
		"email":     "alice@example.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: username") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateLocalUserHandler_MissingFullName(t *testing.T) {
	conn := testconn.New(t)
	res, err := createLocalUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"username": "alice",
		"email":    "alice@example.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: full_name") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateLocalUserHandler_MissingEmail(t *testing.T) {
	conn := testconn.New(t)
	res, err := createLocalUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"username":  "alice",
		"full_name": "Alice Example",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: email") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestCreateLocalUserHandler_CreateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/local-user-store/api/v1/users", func(body any) (any, error) {
		return nil, errors.New("create failed")
	})
	res, err := createLocalUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"username":  "alice",
		"full_name": "Alice Example",
		"email":     "alice@example.com",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to create local user") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
