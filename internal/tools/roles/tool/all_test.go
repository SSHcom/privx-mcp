package tool

import "testing"

func TestAll_ToolNames(t *testing.T) {
	tools := All()
	want := map[string]bool{
		"role-list":    false,
		"role-get":     false,
		"role-members": false,
		"role-create":  false,
		"role-update":  false,
		"role-delete":  false,
		"role-grant":   false,
		"role-revoke":  false,
	}
	if len(tools) != len(want) {
		t.Fatalf("All() returned %d tools, want %d", len(tools), len(want))
	}
	for _, tl := range tools {
		if _, ok := want[tl.Name]; !ok {
			t.Errorf("unexpected tool %q", tl.Name)
			continue
		}
		want[tl.Name] = true
		if tl.Handler == nil {
			t.Errorf("%s: nil handler", tl.Name)
		}
		if tl.InputSchema == nil {
			t.Errorf("%s: nil input schema", tl.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing tool %q", name)
		}
	}
}

func TestWriteFlags(t *testing.T) {
	writeTools := map[string]bool{
		"role-create": true,
		"role-update": true,
		"role-delete": true,
		"role-grant":  true,
		"role-revoke": true,
	}
	for _, tl := range All() {
		wantWrite := writeTools[tl.Name]
		if tl.Writes != wantWrite {
			t.Errorf("%s: Writes = %v, want %v", tl.Name, tl.Writes, wantWrite)
		}
	}
}
