package tool

import "testing"

func TestTargetDomainTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 11 {
		t.Fatalf("expected 11 tools, got %d", len(tools))
	}
	wantNames := []string{
		"target-domain-create",
		"target-domain-delete",
		"target-domain-get",
		"target-domain-list",
		"target-domain-managed-account-checkout",
		"target-domain-managed-account-get",
		"target-domain-managed-account-list",
		"target-domain-managed-account-rotate",
		"target-domain-managed-account-update",
		"target-domain-scan",
		"target-domain-update",
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

func TestTargetDomainTools_WriteFlags(t *testing.T) {
	writeTools := map[string]bool{
		"target-domain-list":                     false,
		"target-domain-get":                      false,
		"target-domain-managed-account-list":     false,
		"target-domain-managed-account-get":      false,
		"target-domain-managed-account-update":   true,
		"target-domain-managed-account-rotate":   true,
		"target-domain-managed-account-checkout": true,
		"target-domain-create":                   true,
		"target-domain-update":                   true,
		"target-domain-delete":                   true,
		"target-domain-scan":                     true,
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
		wantTrusted := tl.Name == "target-domain-managed-account-checkout"
		if tl.Trusted != wantTrusted {
			t.Errorf("tool %q: Trusted = %v, want %v", tl.Name, tl.Trusted, wantTrusted)
		}
	}
}
