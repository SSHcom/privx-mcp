package tool

import "testing"

func TestAll_ToolNames(t *testing.T) {
	tools := All()
	want := map[string]bool{
		"request-create":       false,
		"request-list":         false,
		"request-get":          false,
		"request-search":       false,
		"request-delete":       false,
		"request-revoke-role":  false,
		"request-set-decision": false,
	}
	if len(tools) != len(want) {
		t.Fatalf("All() returned %d tools, want %d", len(tools), len(want))
	}
	for _, tool := range tools {
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool %q", tool.Name)
			continue
		}
		want[tool.Name] = true
		if tool.Handler == nil {
			t.Errorf("%s: nil handler", tool.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing tool %q", name)
		}
	}
}

func TestWriteFlags(t *testing.T) {
	for _, tool := range All() {
		switch tool.Name {
		// request-set-decision mutates via the PrivX API but is intentionally
		// marked read-only so it survives default_read_only mode; see README.
		case "request-create", "request-delete", "request-revoke-role":
			if !tool.Writes {
				t.Errorf("%s: Writes = false, want true", tool.Name)
			}
		default:
			if tool.Writes {
				t.Errorf("%s: Writes = true, want false", tool.Name)
			}
		}
	}
}
