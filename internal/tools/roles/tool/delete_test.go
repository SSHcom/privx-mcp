package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestDeleteRoleHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/roles/:id/members", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{Count: 0, Items: nil}, nil
	})
	conn.Handle("DELETE", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, nil
	})

	res, err := deleteRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "r1" || m["deleted"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestDeleteRoleHandler_RefusesWithMembers(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/roles/:id/members", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{
			Count: 2,
			Items: []rolestore.User{{ID: "u1"}, {ID: "u2"}},
		}, nil
	})

	res, err := deleteRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "refusing to delete role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteRoleHandler_MissingID(t *testing.T) {
	conn := testconn.New(t)
	res, err := deleteRoleHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required field: id") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteRoleHandler_FetchFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, errors.New("not found")
	})
	res, err := deleteRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteRoleHandler_MembersCheckFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/roles/:id/members", func(body any) (any, error) {
		return nil, errors.New("members failed")
	})
	res, err := deleteRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to check role members") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestDeleteRoleHandler_DeleteFails(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return rolestore.Role{ID: "r1", Name: "ops"}, nil
	})
	conn.Handle("GET", "/role-store/api/v1/roles/:id/members", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{Count: 0}, nil
	})
	conn.Handle("DELETE", "/role-store/api/v1/roles/:id", func(body any) (any, error) {
		return nil, errors.New("delete failed")
	})
	res, err := deleteRoleHandler(testconn.CtxWithAuth(conn), map[string]any{"id": "r1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to delete role") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
