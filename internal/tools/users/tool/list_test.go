package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestListUsersHandler(t *testing.T) {
	t.Run("no_auth", func(t *testing.T) {
		res, err := listUsersHandler(testconn.CtxNoAuth(), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected error result")
		}
		if !strings.Contains(res.Content[0].Text, "authentication error") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})

	t.Run("happy", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
			return response.ResultSet[rolestore.User]{
				Count: 3,
				Items: []rolestore.User{
					{ID: "u1", Principal: "alice", SourceType: "LOCAL", FullName: "Alice"},
					{ID: "u2", Principal: "bob", SourceType: "AD", FullName: "Bob"},
					{ID: "u3", Principal: "carol", SourceType: "MICROSOFTGRAPH", FullName: "Carol"},
				},
			}, nil
		})

		res, err := listUsersHandler(testconn.CtxWithAuth(conn), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", res.Content[0].Text)
		}
		m := testconn.DecodeResult(t, res.Content[0].Text)
		if m["count"].(float64) != 3 {
			t.Errorf("count = %v", m["count"])
		}
		if m["limit"].(float64) != float64(common.UsersListLimit) {
			t.Errorf("limit = %v", m["limit"])
		}
		if m["offset"].(float64) != 0 {
			t.Errorf("offset = %v", m["offset"])
		}
		if m["returned"].(float64) != 3 {
			t.Errorf("returned = %v", m["returned"])
		}
		items, ok := m["items"].([]any)
		if !ok || len(items) != 3 {
			t.Fatalf("items = %v", m["items"])
		}
		first, ok := items[0].(map[string]any)
		if !ok {
			t.Fatalf("first item not a map: %T", items[0])
		}
		if first["id"] != "u1" {
			t.Errorf("first id = %v", first["id"])
		}
		if first["principal"] != "alice" {
			t.Errorf("first principal = %v", first["principal"])
		}
		if _, ok := first["roles"]; !ok {
			t.Fatal("roles key must be present")
		}
		if first["roles"] != nil {
			t.Errorf("roles = %v, want null", first["roles"])
		}
	})

	t.Run("fetch_error", func(t *testing.T) {
		conn := testconn.New(t)
		conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
			return nil, errors.New("backend down")
		})
		res, err := listUsersHandler(testconn.CtxWithAuth(conn), map[string]any{})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected error result")
		}
		if !strings.Contains(res.Content[0].Text, "failed to fetch users") {
			t.Errorf("got %q", res.Content[0].Text)
		}
	})
}

func TestListUsersHandler_RawStillRedactsPassword(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{
			Count: 1,
			Items: []rolestore.User{{ID: "u1", Principal: "alice", Password: "secret", Comment: "note"}},
		}, nil
	})

	res, err := listUsersHandler(testconn.CtxWithAuth(conn), map[string]any{"raw": true})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("first item not a map: %T", items[0])
	}
	if _, ok := first["password"]; ok {
		t.Error("raw must still redact password")
	}
	if first["comment"] != "note" {
		t.Errorf("raw should include comment, got %v", first["comment"])
	}
}

func TestListUsersHandler_ExtraFields(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{
			Count: 1,
			Items: []rolestore.User{{ID: "u1", Principal: "alice", Comment: "note"}},
		}, nil
	})

	res, err := listUsersHandler(testconn.CtxWithAuth(conn), map[string]any{"fields": "comment"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	items, _ := m["items"].([]any)
	first, _ := items[0].(map[string]any)
	if first["comment"] != "note" {
		t.Errorf("comment = %v, want note", first["comment"])
	}
}
