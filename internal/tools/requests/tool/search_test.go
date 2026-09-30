package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func TestSearchRequestsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/workflow-engine/api/v1/requests/search", func(body any) (any, error) {
		raw, _ := json.Marshal(body)
		var search workflow.AccessRequestSearch
		if err := json.Unmarshal(raw, &search); err != nil {
			t.Fatalf("unmarshal search: %v", err)
		}
		if search.Keywords != "alice" {
			t.Errorf("keywords = %q, want alice", search.Keywords)
		}
		return response.ResultSet[workflow.AccessRequest]{
			Count: 1,
			Items: []workflow.AccessRequest{sampleRequest()},
		}, nil
	})

	res, err := searchRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": map[string]any{"keywords": "alice"},
		"filter": "ACTIVE_APPROVALS",
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
	if m["filter"] != "active_approvals" {
		t.Errorf("filter = %v", m["filter"])
	}
	if m["limit"].(float64) != 10 {
		t.Errorf("limit = %v", m["limit"])
	}
}

func TestSearchRequestsHandler_DefaultLimit(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/workflow-engine/api/v1/requests/search", func(body any) (any, error) {
		return response.ResultSet[workflow.AccessRequest]{}, nil
	})
	res, err := searchRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["limit"].(float64) != float64(common.RequestsListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}
}

func TestSearchRequestsHandler_InvalidSearchBody(t *testing.T) {
	conn := testconn.New(t)
	res, err := searchRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"search": "not-an-object",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "invalid search body") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestSearchRequestsHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/workflow-engine/api/v1/requests/search", func(body any) (any, error) {
		return nil, errors.New("backend down")
	})
	res, err := searchRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to search access requests") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestSearchRequestsHandler_NextOffset(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("POST", "/workflow-engine/api/v1/requests/search", func(body any) (any, error) {
		return response.ResultSet[workflow.AccessRequest]{
			Count: 5,
			Items: []workflow.AccessRequest{{ID: "req-1"}, {ID: "req-2"}},
		}, nil
	})
	res, err := searchRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{
		"limit":  2,
		"offset": 0,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["remaining"].(float64) != 3 {
		t.Errorf("remaining = %v, want 3", m["remaining"])
	}
	if m["nextOffset"].(float64) != 2 {
		t.Errorf("nextOffset = %v, want 2", m["nextOffset"])
	}
}
