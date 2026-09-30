package requests

import (
	"github.com/SSHcom/privx-sdk-go/v2/api/workflow"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Default field sets always returned by request-list and
// request-search when callers do not request raw output.
var (
	DefaultRequestFields = []string{
		"id",
		"requester",
		"requested_role",
		"steps",
	}
	DefaultStepFields = []string{
		"id",
		"name",
		"approvers",
	}
	DefaultApproverFields = []string{
		"id",
		"decision",
	}
)

// Projection is the request/step/approver field sets for list and search.
type Projection struct {
	Root      []string
	Steps     []string
	Approvers []string
}

// ProjectionFromParams merges default request field sets with optional CSV extras.
func ProjectionFromParams(params map[string]any) Projection {
	return Projection{
		Root:      utils.MergeUnique(DefaultRequestFields, utils.CSVFromMap(params, "fields")),
		Steps:     utils.MergeUnique(DefaultStepFields, utils.CSVFromMap(params, "stepFields")),
		Approvers: utils.MergeUnique(DefaultApproverFields, utils.CSVFromMap(params, "approverFields")),
	}
}

// SelectRequestFields builds a filtered access-request map containing every
// requested root field. Absent or JSON-null values are emitted as null (never
// omitted). When steps is a non-null array it is projected with stepFields and
// nested approvers with approverFields.
func SelectRequestFields(request map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Root))
	for _, field := range p.Root {
		switch field {
		case "steps":
			out["steps"] = selectStepsField(request["steps"], p)
		default:
			if value, ok := request[field]; ok {
				out[field] = value
			} else {
				out[field] = nil
			}
		}
	}

	return out
}

func selectStepsField(raw any, p Projection) any {
	if raw == nil {
		return nil
	}

	steps, ok := raw.([]any)
	if !ok {
		return nil
	}

	selected := make([]any, 0, len(steps))
	for _, item := range steps {
		step, ok := item.(map[string]any)
		if !ok {
			continue
		}

		selected = append(selected, selectStepFields(step, p))
	}

	return selected
}

func selectStepFields(step map[string]any, p Projection) map[string]any {
	out := make(map[string]any, len(p.Steps))
	for _, field := range p.Steps {
		switch field {
		case "approvers":
			out["approvers"] = common.ProjectArray(step["approvers"], p.Approvers, common.NullMissing)
		default:
			if value, ok := step[field]; ok {
				out[field] = value
			} else {
				out[field] = nil
			}
		}
	}

	return out
}

// FormatRequestItems converts access requests to response maps. When raw is
// false, fields are projected with SelectRequestFields.
func FormatRequestItems(items []workflow.AccessRequest, raw bool, p Projection) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		requestMap := utils.ToJSONMap(item)
		if !raw {
			requestMap = SelectRequestFields(requestMap, p)
		}

		out = append(out, requestMap)
	}

	return out
}
