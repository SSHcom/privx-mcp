package tool

import (
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func waitingRequest() *workflow.AccessRequest {
	return &workflow.AccessRequest{
		ID:     "req-1",
		Status: "WAITING",
		Steps: []workflow.RequestStep{
			{
				ID:   "step-1",
				Name: "Linux Demo",
				Approvers: []workflow.RequestStepApprover{
					{
						ID:       "appr-1",
						Decision: "WAITING",
						Role: workflow.WorkflowRole{
							ID:   "role-admin",
							Name: "privx-admin",
						},
					},
				},
			},
		},
	}
}

func TestSetRequestDecisionHandler_Happy(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(any) (any, error) {
		return waitingRequest(), nil
	})
	var posted atomic.Bool
	conn.Handle("POST", "/workflow-engine/api/v1/requests/:id/decision", func(body any) (any, error) {
		posted.Store(true)
		raw, _ := json.Marshal(body)
		var d workflow.Decision
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("unmarshal decision: %v", err)
		}
		if d.Step != 0 || d.Decision != "APPROVED" || d.Comment != "ok" {
			t.Errorf("decision = %+v", d)
		}
		return nil, nil
	})

	ctx := testconn.CtxWithAuthRoles(conn, []auth.Role{{ID: "role-admin", Name: "privx-admin"}})
	res, err := setRequestDecisionHandler(ctx, map[string]any{
		"id":       "req-1",
		"step":     0,
		"decision": "APPROVED",
		"comment":  "ok",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !posted.Load() {
		t.Fatal("expected decision POST")
	}
	m := testconn.DecodeResult(t, res.Content[0].Text)
	if m["id"] != "req-1" || m["decision"] != "APPROVED" {
		t.Errorf("result = %v", m)
	}
	if step, ok := m["step"].(float64); !ok || step != 0 {
		t.Errorf("step = %v", m["step"])
	}
}

func TestSetRequestDecisionHandler_MissingFields(t *testing.T) {
	conn := testconn.New(t)
	ctx := testconn.CtxWithAuthRoles(conn, []auth.Role{{ID: "role-admin", Name: "privx-admin"}})

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"missing id", map[string]any{"step": 0, "decision": "APPROVED"}, "missing required field: id"},
		{"missing step", map[string]any{"id": "req-1", "decision": "APPROVED"}, "missing required field: step"},
		{"missing decision", map[string]any{"id": "req-1", "step": 0}, "missing required field: decision"},
		{"bad decision", map[string]any{"id": "req-1", "step": 0, "decision": "MAYBE"}, "invalid decision"},
		{"waiting not allowed", map[string]any{"id": "req-1", "step": 0, "decision": "WAITING"}, "invalid decision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := setRequestDecisionHandler(ctx, tc.params)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !res.IsError {
				t.Fatal("expected error result")
			}
			if !strings.Contains(res.Content[0].Text, tc.want) {
				t.Fatalf("got %q, want substring %q", res.Content[0].Text, tc.want)
			}
		})
	}
}

func TestSetRequestDecisionHandler_NotWaiting(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(any) (any, error) {
		req := waitingRequest()
		req.Status = "APPROVED"
		return req, nil
	})
	conn.Handle("POST", "/workflow-engine/api/v1/requests/:id/decision", func(any) (any, error) {
		t.Fatal("decision POST must not be called")
		return nil, nil
	})

	ctx := testconn.CtxWithAuthRoles(conn, []auth.Role{{ID: "role-admin", Name: "privx-admin"}})
	res, err := setRequestDecisionHandler(ctx, map[string]any{
		"id": "req-1", "step": 0, "decision": "APPROVED",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "must be WAITING") {
		t.Fatalf("got %q", res.Content[0].Text)
	}
}

func TestSetRequestDecisionHandler_BadStep(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(any) (any, error) {
		return waitingRequest(), nil
	})
	conn.Handle("POST", "/workflow-engine/api/v1/requests/:id/decision", func(any) (any, error) {
		t.Fatal("decision POST must not be called")
		return nil, nil
	})

	ctx := testconn.CtxWithAuthRoles(conn, []auth.Role{{ID: "role-admin", Name: "privx-admin"}})
	res, err := setRequestDecisionHandler(ctx, map[string]any{
		"id": "req-1", "step": 3, "decision": "APPROVED",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "out of range") {
		t.Fatalf("got %q", res.Content[0].Text)
	}
}

func TestSetRequestDecisionHandler_MissingRole(t *testing.T) {
	conn := testconn.New(t)
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(any) (any, error) {
		return waitingRequest(), nil
	})
	conn.Handle("POST", "/workflow-engine/api/v1/requests/:id/decision", func(any) (any, error) {
		t.Fatal("decision POST must not be called")
		return nil, nil
	})

	ctx := testconn.CtxWithAuthRoles(conn, []auth.Role{{ID: "other", Name: "not-approver"}})
	res, err := setRequestDecisionHandler(ctx, map[string]any{
		"id": "req-1", "step": 0, "decision": "DENIED",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "missing required approver role") {
		t.Fatalf("got %q", res.Content[0].Text)
	}
}

func TestSetRequestDecisionHandler_GetFails(t *testing.T) {
	conn := testconn.New(t)
	inner := errors.New("not found")
	conn.Handle("GET", "/workflow-engine/api/v1/requests/:id", func(any) (any, error) {
		return nil, inner
	})

	ctx := testconn.CtxWithAuthRoles(conn, []auth.Role{{ID: "role-admin", Name: "privx-admin"}})
	res, err := setRequestDecisionHandler(ctx, map[string]any{
		"id": "req-1", "step": 0, "decision": "APPROVED",
	})
	if err == nil {
		t.Fatalf("expected operational error, got result %#v", res)
	}
	if !strings.Contains(err.Error(), "failed to fetch access request") {
		t.Fatalf("got %v", err)
	}
	if !errors.Is(err, inner) {
		t.Errorf("expected wrapped cause, got %v", err)
	}
}

func TestSetDecision_ToolMetadata(t *testing.T) {
	tool := SetDecision()
	if tool.Name != "request-set-decision" {
		t.Errorf("name = %q", tool.Name)
	}
	// Intentionally read-only despite mutating the request; see README
	// ("Why request-set-decision is classified as Read").
	if tool.Writes {
		t.Error("Writes = true, want false")
	}
	if tool.Handler == nil {
		t.Error("nil handler")
	}
	if !strings.Contains(tool.Description, "request-search") {
		t.Error("description should mention request-search")
	}
	if !strings.Contains(tool.Description, "mcp-info") {
		t.Error("description should mention mcp-info as optional")
	}
}
