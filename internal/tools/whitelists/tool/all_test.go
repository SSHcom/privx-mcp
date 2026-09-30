package tool

import "testing"

func TestWhitelistTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(tools))
	}
	wantNames := []string{
		"whitelist-create", "whitelist-delete", "whitelist-evaluate",
		"whitelist-get", "whitelist-list", "whitelist-search", "whitelist-update",
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

func TestWhitelistTools_WriteFlags(t *testing.T) {
	tools := All()
	writeTools := map[string]bool{
		"whitelist-create":   true,
		"whitelist-update":   true,
		"whitelist-delete":   true,
		"whitelist-list":     false,
		"whitelist-get":      false,
		"whitelist-search":   false,
		"whitelist-evaluate": false,
	}
	for _, tl := range tools {
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
