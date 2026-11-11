package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/SSHcom/privx-sdk-go/v2/api/vault"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestUserSecrets_GlobalOmitsUserID(t *testing.T) {
	conn := testconn.New(t)
	ctx := testconn.CtxWithAuth(conn)
	conn.Handle("GET", "/vault/api/v1/secrets", func(body any) (any, error) {
		return response.ResultSet[vault.Secret]{
			Count: 1,
			Items: []vault.Secret{{SecretRequest: vault.SecretRequest{Name: "shared"}}},
		}, nil
	})
	conn.Handle("GET", "/vault/api/v1/secrets/:name", func(body any) (any, error) {
		return vault.Secret{SecretRequest: vault.SecretRequest{Name: "shared"}}, nil
	})
	conn.Handle("POST", "/vault/api/v1/secrets", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		var req vault.SecretRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if req.OwnerID != "" {
			t.Errorf("owner_id = %q, want empty", req.OwnerID)
		}
		if req.Name != "shared" {
			t.Errorf("name = %q", req.Name)
		}
		return vault.SecretCreate{Name: "shared"}, nil
	})

	listRes, err := listHandler(ctx, map[string]any{})
	if err != nil || listRes.IsError {
		t.Fatalf("list: err=%v res=%v", err, listRes)
	}
	getRes, err := getHandler(ctx, map[string]any{"name": "shared"})
	if err != nil || getRes.IsError {
		t.Fatalf("get: err=%v res=%v", err, getRes)
	}
	createRes, err := createHandler(ctx, map[string]any{"name": "shared"})
	if err != nil || createRes.IsError {
		t.Fatalf("create: err=%v res=%v", err, createRes)
	}
}

func TestListUserSecrets_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/vault/api/v1/user/:userID/secrets", func(body any) (any, error) {
		data := map[string]any{"password": "secret"}
		return response.ResultSet[vault.Secret]{
			Count: 1,
			Items: []vault.Secret{{
				SecretRequest: vault.SecretRequest{Name: "db", Data: &data},
			}},
		}, nil
	})

	res, err := listHandler(testconn.CtxWithAuth(conn), map[string]any{"user_id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["count"].(float64) != 1 {
		t.Errorf("count = %v", m["count"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
	item := items[0].(map[string]any)
	if item["name"] != "db" {
		t.Errorf("name = %v", item["name"])
	}
	data, ok := item["data"].(map[string]any)
	if !ok || data["password"] != "secret" {
		t.Errorf("data = %v", item["data"])
	}
}

func TestGetUserSecret_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/vault/api/v1/user/:userID/secrets/:name", func(body any) (any, error) {
		data := map[string]any{"token": "abc"}
		return vault.Secret{
			SecretRequest: vault.SecretRequest{Name: "api", Data: &data},
		}, nil
	})

	res, err := getHandler(testconn.CtxWithAuth(conn), map[string]any{"user_id": "u1", "name": "api"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["name"] != "api" {
		t.Errorf("name = %v", m["name"])
	}
}

func TestCreateUserSecret_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/vault/api/v1/user/:userID/secrets", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		var req vault.SecretRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if req.Name != "db" {
			t.Errorf("name = %q", req.Name)
		}
		if req.OwnerID != "u1" {
			t.Errorf("owner_id = %q, want u1", req.OwnerID)
		}
		if req.Data == nil || (*req.Data)["password"] != "secret" {
			t.Errorf("data = %v", req.Data)
		}
		nested, _ := (*req.Data)["nested"].(map[string]any)
		if nested["k"] != "v" {
			t.Errorf("nested data = %v", (*req.Data)["nested"])
		}
		if len(req.ReadRoles) != 1 || req.ReadRoles[0].ID != "r1" || req.ReadRoles[0].Name != "readers" || req.ReadRoles[0].Deleted {
			t.Errorf("read_roles = %+v", req.ReadRoles)
		}
		if len(req.WriteRoles) != 0 {
			t.Errorf("write_roles = %+v", req.WriteRoles)
		}
		return vault.SecretCreate{Name: "db"}, nil
	})

	res, err := createHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":  "u1",
		"name":     "db",
		"owner_id": "someone-else",
		"data": map[string]any{
			"password": "secret",
			"nested":   map[string]any{"k": "v"},
		},
		"read_roles": []any{
			map[string]any{"id": "r1", "name": "readers", "deleted": true},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["name"] != "db" {
		t.Errorf("name = %v", m["name"])
	}
}

func TestCreateUserSecret_Validation(t *testing.T) {
	conn := testconn.New(t)
	ctx := testconn.CtxWithAuth(conn)
	cases := []map[string]any{
		{"user_id": "u1"},
		{"user_id": "u1", "name": "db", "data": "nope"},
		{"user_id": "u1", "name": "db", "read_roles": []any{map[string]any{"name": "readers"}}},
	}
	for _, params := range cases {
		res, err := createHandler(ctx, params)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError || !strings.Contains(res.Content[0].Text, "validation error:") {
			t.Errorf("params %v: got error=%v text=%q", params, res.IsError, res.Content[0].Text)
		}
	}
}

func TestUpdateUserSecret_Happy(t *testing.T) {
	conn := testconn.New(t)
	stored := map[string]any{"password": "old"}
	conn.Handle("GET", "/vault/api/v1/user/:userID/secrets/:name", func(body any) (any, error) {
		return vault.Secret{SecretRequest: vault.SecretRequest{
			Name:       "db",
			OwnerID:    "other",
			Data:       &stored,
			ReadRoles:  []rolestore.RoleHandle{{ID: "r1", Name: "readers"}},
			WriteRoles: []rolestore.RoleHandle{{ID: "w1", Name: "writers"}},
		}}, nil
	})
	conn.Handle("PUT", "/vault/api/v1/user/:userID/secrets/:name", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		var req vault.SecretRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if req.Name != "db" || req.OwnerID != "u1" {
			t.Errorf("name=%q owner_id=%q", req.Name, req.OwnerID)
		}
		if req.Data == nil || (*req.Data)["password"] != "new" {
			t.Errorf("data = %v", req.Data)
		}
		if len(req.ReadRoles) != 1 || req.ReadRoles[0].ID != "r1" {
			t.Errorf("read_roles = %+v", req.ReadRoles)
		}
		if len(req.WriteRoles) != 1 || req.WriteRoles[0].ID != "w2" || req.WriteRoles[0].Name != "" {
			t.Errorf("write_roles = %+v", req.WriteRoles)
		}
		return nil, nil
	})

	res, err := updateHandler(testconn.CtxWithAuth(conn), map[string]any{
		"user_id":     "u1",
		"name":        "db",
		"owner_id":    "someone-else",
		"data":        map[string]any{"password": "new"},
		"write_roles": []any{map[string]any{"id": "w2", "deleted": true}},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["name"] != "db" || m["updated"] != true {
		t.Errorf("result = %v", m)
	}
}

func TestUpdateUserSecret_GlobalOmitsOwnerID(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/vault/api/v1/secrets/:name", func(body any) (any, error) {
		return vault.Secret{SecretRequest: vault.SecretRequest{
			Name:      "shared",
			ReadRoles: []rolestore.RoleHandle{{ID: "r1", Name: "privx-admin"}},
		}}, nil
	})
	conn.Handle("PUT", "/vault/api/v1/secrets/:name", func(body any) (any, error) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		if strings.Contains(string(raw), "owner_id") {
			t.Errorf("global update body includes owner_id: %s", raw)
		}
		var req vault.SecretRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		if len(req.ReadRoles) != 1 || req.ReadRoles[0].ID != "r1" {
			t.Errorf("read_roles = %+v", req.ReadRoles)
		}
		if req.Data == nil || (*req.Data)["purpose"] != "updated" {
			t.Errorf("data = %v", req.Data)
		}
		return nil, nil
	})

	res, err := updateHandler(testconn.CtxWithAuth(conn), map[string]any{
		"name": "shared",
		"data": map[string]any{"purpose": "updated"},
	})
	if err != nil || res.IsError {
		t.Fatalf("update: err=%v res=%v", err, res)
	}
}

func TestUpdateUserSecret_Validation(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/vault/api/v1/user/:userID/secrets/:name", func(body any) (any, error) {
		return vault.Secret{SecretRequest: vault.SecretRequest{Name: "db"}}, nil
	})
	ctx := testconn.CtxWithAuth(conn)
	cases := []map[string]any{
		{"user_id": "u1"},
		{"user_id": "u1", "name": "db", "data": "nope"},
		{"user_id": "u1", "name": "db", "read_roles": []any{map[string]any{"name": "readers"}}},
	}
	for _, params := range cases {
		res, err := updateHandler(ctx, params)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !res.IsError || !strings.Contains(res.Content[0].Text, "validation error:") {
			t.Errorf("params %v: got error=%v text=%q", params, res.IsError, res.Content[0].Text)
		}
	}
}

func TestDeleteUserSecret_PersonalAndGlobal(t *testing.T) {
	conn := testconn.New(t)
	ctx := testconn.CtxWithAuth(conn)
	conn.Handle("DELETE", "/vault/api/v1/user/:userID/secrets/:name", func(body any) (any, error) {
		return nil, nil
	})
	conn.Handle("DELETE", "/vault/api/v1/secrets/:name", func(body any) (any, error) {
		return nil, nil
	})

	personal, err := deleteHandler(ctx, map[string]any{"user_id": "u1", "name": "db"})
	if err != nil || personal.IsError {
		t.Fatalf("personal: err=%v res=%v", err, personal)
	}
	global, err := deleteHandler(ctx, map[string]any{"name": "shared"})
	if err != nil || global.IsError {
		t.Fatalf("global: err=%v res=%v", err, global)
	}
	missing, err := deleteHandler(ctx, map[string]any{"user_id": "u1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !missing.IsError || !strings.Contains(missing.Content[0].Text, "validation error:") {
		t.Fatalf("missing name: %v", missing)
	}
}
