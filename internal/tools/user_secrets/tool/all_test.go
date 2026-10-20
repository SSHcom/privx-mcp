package tool

import "testing"

func TestUserSecretTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 5 {
		t.Fatalf("expected 5 tools, got %d", len(tools))
	}
	wantNames := []string{
		"user-secret-list",
		"user-secret-get",
		"user-secret-create",
		"user-secret-update",
		"user-secret-delete",
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

func TestUserSecretTools_Flags(t *testing.T) {
	writeTools := map[string]bool{
		"user-secret-list":   false,
		"user-secret-get":    false,
		"user-secret-create": true,
		"user-secret-update": true,
		"user-secret-delete": true,
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
		if !tl.Sensitive {
			t.Errorf("tool %q: Sensitive = false, want true", tl.Name)
		}
		if tl.Trusted {
			t.Errorf("tool %q: Trusted = true, want false", tl.Name)
		}
	}
}
