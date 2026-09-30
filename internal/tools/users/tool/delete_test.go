package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/userstore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeleteUserHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return userstore.LocalUser{ID: "u1", Principal: "alice"}, nil
	})
	conn.Handle("DELETE", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return nil, nil
	})
	res, err := deleteUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
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
	if m["deleted"] != true {
		t.Errorf("deleted = %v, want true", m["deleted"])
	}
}

func TestDeleteUserHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteUserHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteUserHandler_UserMissing(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := deleteUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch local user") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteUserHandler_DeleteFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return userstore.LocalUser{ID: "u1"}, nil
	})
	conn.Handle("DELETE", "/local-user-store/api/v1/users/:id", func(body any) (any, error) {
		return nil, errors.New("delete failed")
	})
	res, err := deleteUserHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to delete local user") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
