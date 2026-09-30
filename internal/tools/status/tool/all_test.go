package tool

import "testing"

func TestStatusTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}
	wantNames := []string{"status-components", "status-instance", "status-monitor-service"}
	gotNames := make([]string, 0, len(tools))
	for _, tl := range tools {
		gotNames = append(gotNames, tl.Name)
		if tl.Handler == nil {
			t.Errorf("tool %q has nil handler", tl.Name)
		}
		if tl.InputSchema == nil {
			t.Errorf("tool %q has nil input schema", tl.Name)
		}
	}
	for _, want := range wantNames {
		found := false
		for _, got := range gotNames {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing tool %q in %v", want, gotNames)
		}
	}
}

func TestStatusTools_WriteFlags(t *testing.T) {
	tools := All()
	for _, tl := range tools {
		if tl.Writes {
			t.Errorf("tool %q: Writes = true, want false", tl.Name)
		}
	}
}
