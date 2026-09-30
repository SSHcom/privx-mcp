package tool

import "testing"

func TestNetworkTargetTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 6 {
		t.Fatalf("expected 6 tools, got %d", len(tools))
	}
	wantNames := []string{
		"network-target-create",
		"network-target-delete",
		"network-target-get",
		"network-target-list",
		"network-target-search",
		"network-target-update",
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

func TestNetworkTargetTools_WriteFlags(t *testing.T) {
	writeTools := map[string]bool{
		"network-target-create": true,
		"network-target-update": true,
		"network-target-delete": true,
		"network-target-list":   false,
		"network-target-get":    false,
		"network-target-search": false,
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
