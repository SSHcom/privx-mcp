package tool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestSearchUsersHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var us rolestore.UserSearch
		_ = json.Unmarshal(raw, &us)
		if us.Keywords != "alice" {
			t.Errorf("search body keywords = %q, want alice", us.Keywords)
		}
		return response.ResultSet[rolestore.User]{
			Count: 1,
			Items: []rolestore.User{{ID: "u1", Principal: "alice", SourceType: "LOCAL"}},
		}, nil
	})
	res, err := searchUsersHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": map[string]any{"keywords": "alice"},
		"limit":  float64(10),
	})
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
	if m["nextOffset"] != nil {
		t.Errorf("nextOffset = %v, want null on last page", m["nextOffset"])
	}
	items := m["items"].([]any)
	first := items[0].(map[string]any)
	if first["roles"] != nil {
		t.Errorf("roles = %v, want null", first["roles"])
	}
}

func TestSearchUsersHandler_PaginationMetadata(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
		return response.ResultSet[rolestore.User]{
			Count: 82,
			Items: make([]rolestore.User, 50),
		}, nil
	})

	res, err := searchUsersHandler(testconn.CtxWithAuth(conn), map[string]any{
		"limit":  float64(50),
		"offset": float64(0),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["returned"].(float64) != 50 {
		t.Errorf("returned = %v, want 50", m["returned"])
	}
	if m["remaining"].(float64) != 32 {
		t.Errorf("remaining = %v, want 32", m["remaining"])
	}
	if m["pagesRemaining"].(float64) != 1 {
		t.Errorf("pagesRemaining = %v, want 1", m["pagesRemaining"])
	}
	if m["nextOffset"].(float64) != 50 {
		t.Errorf("nextOffset = %v, want 50 (not 1)", m["nextOffset"])
	}
}

func TestSearchUsersHandler_InvalidSearchBody(t *testing.T) {
	conn := testconn.New(t)
	res, err := searchUsersHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": []any{"not-an-object"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected error for non-object search")
	}
	if !strings.Contains(res.Content[0].Text, "invalid search body") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestSearchUsersHandler_SourceTypePostFilter(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/role-store/api/v1/users/search", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var us rolestore.UserSearch
		_ = json.Unmarshal(raw, &us)
		if us.Keywords != "alice" {
			t.Errorf("search body keywords = %q, want alice", us.Keywords)
		}
		// source_type must not be forwarded to PrivX UserSearch.
		var rawMap map[string]any
		_ = json.Unmarshal(raw, &rawMap)
		if _, ok := rawMap["source_type"]; ok {
			t.Errorf("source_type was sent to PrivX: %v", rawMap)
		}
		return response.ResultSet[rolestore.User]{
			Count: 82,
			Items: []rolestore.User{
				{ID: "u1", Principal: "alice", SourceType: "LOCAL"},
				{ID: "u2", Principal: "alice.ad", SourceType: "AD"},
				{ID: "u3", Principal: "alice.mg", SourceType: "MICROSOFTGRAPH"},
			},
		}, nil
	})

	res, err := searchUsersHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": map[string]any{"keywords": "alice", "source_type": "ad"},
		"limit":  float64(50),
		"offset": float64(0),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}

	m := testconn.DecodeResult(t, res.Content[0].Text)
	// count/remaining/pagesRemaining follow the unfiltered PrivX page.
	if m["count"].(float64) != 82 {
		t.Errorf("count = %v, want 82", m["count"])
	}
	if m["returned"].(float64) != 1 {
		t.Errorf("returned = %v, want 1", m["returned"])
	}
	if m["remaining"].(float64) != 79 {
		t.Errorf("remaining = %v, want 79 (82 - 3 fetched)", m["remaining"])
	}
	if m["pagesRemaining"].(float64) != 2 {
		t.Errorf("pagesRemaining = %v, want 2", m["pagesRemaining"])
	}
	if m["nextOffset"].(float64) != 3 {
		t.Errorf("nextOffset = %v, want 3 (offset + unfiltered fetched)", m["nextOffset"])
	}
	items := m["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	first := items[0].(map[string]any)
	if first["id"] != "u2" {
		t.Errorf("id = %v, want u2", first["id"])
	}
	if first["source_type"] != "AD" {
		t.Errorf("source_type = %v, want AD", first["source_type"])
	}
}
