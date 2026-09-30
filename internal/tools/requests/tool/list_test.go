package tool

import (
	"errors"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
)

func sampleRequest() workflow.AccessRequest {
	return workflow.AccessRequest{
		ID:     "req-1",
		Status: "WAITING",
		Requester: &workflow.WorkflowUser{
			ID:          "u1",
			DisplayName: "Alice",
		},
		RequestedRole: &workflow.WorkflowRole{
			ID:   "r1",
			Name: "Linux-Admin",
		},
		Steps: []workflow.RequestStep{
			{
				ID:   "step-1",
				Name: "Approve",
				Approvers: []workflow.RequestStepApprover{
					{ID: "appr-1", Decision: "WAITING"},
				},
			},
		},
	}
}

func TestListRequestsHandler_NoAuth(t *testing.T) {
	res, err := listRequestsHandler(testconn.CtxNoAuth(), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "authentication error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListRequestsHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests", func(body any) (any, error) {
		return response.ResultSet[workflow.AccessRequest]{
			Count: 1,
			Items: []workflow.AccessRequest{sampleRequest()},
		}, nil
	})

	res, err := listRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{})
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
	if m["limit"].(float64) != float64(common.RequestsListLimit) {
		t.Errorf("limit = %v", m["limit"])
	}
	if m["filter"] != "all" {
		t.Errorf("filter = %v, want all", m["filter"])
	}
	items, ok := m["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", m["items"])
	}
	first := items[0].(map[string]any)
	if first["id"] != "req-1" {
		t.Errorf("id = %v", first["id"])
	}
}

func TestListRequestsHandler_InvalidFilter(t *testing.T) {
	conn := testconn.New(t)
	res, err := listRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{"filter": "NOPE"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "validation error") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestListRequestsHandler_FetchError(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests", func(body any) (any, error) {
		return nil, errors.New("backend down")
	})
	res, err := listRequestsHandler(testconn.CtxWithAuth(conn), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "failed to fetch access requests") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
