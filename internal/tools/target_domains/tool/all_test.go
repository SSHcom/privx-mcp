package tool

import "testing"

func TestTargetDomainTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	wantNames := []string{"target-domain-get", "target-domain-list"}
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

func TestTargetDomainTools_WriteFlags(t *testing.T) {
	for _, tl := range All() {
		if tl.Writes {
			t.Errorf("tool %q: Writes = true, want false", tl.Name)
		}
	}
}
