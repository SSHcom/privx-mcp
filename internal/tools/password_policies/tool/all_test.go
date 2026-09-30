package tool

import "testing"

func TestPasswordPolicyTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 5 {
		t.Fatalf("expected 5 tools, got %d", len(tools))
	}
	wantNames := []string{
		"password-policy-create",
		"password-policy-delete",
		"password-policy-get",
		"password-policy-list",
		"password-policy-update",
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

func TestPasswordPolicyTools_WriteFlags(t *testing.T) {
	tools := All()
	writeTools := map[string]bool{
		"password-policy-list":   false,
		"password-policy-get":    false,
		"password-policy-create": true,
		"password-policy-update": true,
		"password-policy-delete": true,
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
