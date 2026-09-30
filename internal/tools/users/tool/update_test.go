package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestUpdateUserHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return userstore.LocalUser{
			ID:                     "u1",
			Principal:              "alice",
			FullName:               "Old Name",
			Email:                  "alice@example.com",
			Company:                "Acme",
			Password:               userstore.LocalUserPassword{Password: "secret"},
			PasswordChangeRequired: false,
		}, nil
	})
	conn.Handle("PUT", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var u userstore.LocalUser
		if err := json.Unmarshal(raw, &u); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if u.FullName != "New Name" {
			t.Errorf("full_name = %q, want New Name", u.FullName)
		}
		if u.Company != "Acme" {
			t.Errorf("company = %q, want preserved Acme", u.Company)
		}
		if u.Principal != "alice" {
			t.Errorf("username = %q, want preserved alice", u.Principal)
		}
		if u.Password.Password != "secret" {
			t.Errorf("password = %q, want preserved", u.Password.Password)
		}
		if u.PasswordChangeRequired {
			t.Error("password_change_required changed, want preserved false")
		}
		return nil, nil
	})

	res, err := updateUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":        "u1",
		"full_name": "New Name",
	})
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
	if m["updated"] != true {
		t.Errorf("updated = %v, want true", m["updated"])
	}
}

func TestUpdateUserHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := updateUserHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateUserHandler_FetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := updateUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch local user") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateUserHandler_BadTags(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return userstore.LocalUser{ID: "u1"}, nil
	})
	res, err := updateUserHandler(testconn.CtxWithAuth(conn), map[string]any{
		"id":   "u1",
		"tags": "not-an-array",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "tags") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestUpdateUserHandler_UpdateFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return userstore.LocalUser{ID: "u1"}, nil
	})
	conn.Handle("PUT", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return nil, errors.New("put failed")
	})
	res, err := updateUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to update local user") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
