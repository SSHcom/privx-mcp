package tool

import "testing"

func TestAccessGroupTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 5 {
		t.Fatalf("expected 5 tools, got %d", len(tools))
	}
	wantNames := []string{
		"access-group-list",
		"access-group-get",
		"access-group-create",
		"access-group-update",
		"access-group-delete",
	}
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

func TestAccessGroupTools_WriteFlags(t *testing.T) {
	writeTools := map[string]bool{
		"access-group-list":   false,
		"access-group-get":    false,
		"access-group-create": true,
		"access-group-update": true,
		"access-group-delete": true,
	}
	for _, tl := range All() {
		want, ok := writeTools[tl.Name]
		if !ok {
			t.Errorf("unexpected tool %q", tl.Name)
			continue
		}
		if tl.Writes != want {
			t.Errorf("tool %q: Writes = %v, want %v", tl.Name, tl.Writes, want)
		}
	}
}
