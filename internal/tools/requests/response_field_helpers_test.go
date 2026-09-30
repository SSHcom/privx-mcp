package requests

import (
	"encoding/json"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
)

func TestSelectRequestFields_Defaults(t *testing.T) {
	request := map[string]any{
		"id": "req-1",
		"requester": map[string]any{
			"id":           "user-1",
			"display_name": "Ada Lovelace",
		},
		"requested_role": map[string]any{
			"id":   "role-1",
			"name": "admin",
		},
		"status": "PENDING",
		"steps": []any{
			map[string]any{
				"id":    "step-1",
				"name":  "Manager approval",
				"match": "ANY",
				"approvers": []any{
					map[string]any{
						"id":       "appr-1",
						"decision": "PENDING",
						"comment":  "x",
					},
				},
			},
		},
	}

	out := SelectRequestFields(request, ProjectionFromParams(nil))
	if _, ok := out["status"]; ok {
		t.Error("status should be dropped by default root fields")
	}
	if out["id"] != "req-1" {
		t.Errorf("id = %v", out["id"])
	}
	requester, ok := out["requester"].(map[string]any)
	if !ok || requester["id"] != "user-1" {
		t.Fatalf("requester = %v", out["requester"])
	}
	role, ok := out["requested_role"].(map[string]any)
	if !ok || role["id"] != "role-1" {
		t.Fatalf("requested_role = %v", out["requested_role"])
	}

	steps, ok := out["steps"].([]any)
	if !ok || len(steps) != 1 {
		t.Fatalf("steps = %v", out["steps"])
	}
	step, ok := steps[0].(map[string]any)
	if !ok {
		t.Fatalf("step not a map: %T", steps[0])
	}
	if step["id"] != "step-1" || step["name"] != "Manager approval" {
		t.Errorf("step = %v", step)
	}
	if _, ok := step["match"]; ok {
		t.Error("match should not be projected by default step fields")
	}

	approvers, ok := step["approvers"].([]any)
	if !ok || len(approvers) != 1 {
		t.Fatalf("approvers = %v", step["approvers"])
	}
	approver, ok := approvers[0].(map[string]any)
	if !ok {
		t.Fatalf("approver not a map: %T", approvers[0])
	}
	if approver["id"] != "appr-1" || approver["decision"] != "PENDING" {
		t.Errorf("approver = %v", approver)
	}
	if _, ok := approver["comment"]; ok {
		t.Error("comment should not be projected by default approver fields")
	}
}

func TestSelectRequestFields_MalformedSteps(t *testing.T) {
	out := SelectRequestFields(map[string]any{"steps": "nope"}, Projection{Root: []string{"steps"}})
	if out["steps"] != nil {
		t.Errorf("malformed steps = %v, want null", out["steps"])
	}
}

func TestSelectRequestFields_NullSteps(t *testing.T) {
	out := SelectRequestFields(map[string]any{"id": "req-1"}, Projection{
		Root:      []string{"id", "steps"},
		Steps:     DefaultStepFields,
		Approvers: DefaultApproverFields,
	})
	if v, ok := out["steps"]; !ok {
		t.Fatal("steps key must be present")
	} else if v != nil {
		t.Errorf("steps = %v, want null", v)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["steps"] != nil {
		t.Errorf("JSON steps = %v, want null", decoded["steps"])
	}
}

func TestFormatRequestItems_RawAndProjected(t *testing.T) {
	items := []workflow.AccessRequest{
		{
			ID: "req-1",
			RequestedRole: &workflow.WorkflowRole{
				ID:   "role-1",
				Name: "admin",
			},
			Status: "PENDING",
			Steps: []workflow.RequestStep{
				{
					ID:   "step-1",
					Name: "Approve",
					Approvers: []workflow.RequestStepApprover{
						{ID: "appr-1", Decision: "PENDING"},
					},
				},
			},
		},
	}

	raw := FormatRequestItems(items, true, ProjectionFromParams(nil))
	if len(raw) != 1 {
		t.Fatalf("raw len = %d", len(raw))
	}
	if raw[0]["status"] != "PENDING" {
		t.Errorf("raw status = %v", raw[0]["status"])
	}

	projected := FormatRequestItems(items, false, ProjectionFromParams(nil))
	if _, ok := projected[0]["status"]; ok {
		t.Error("projected status should be absent")
	}
	if projected[0]["id"] != "req-1" {
		t.Errorf("projected id = %v", projected[0]["id"])
	}
}
