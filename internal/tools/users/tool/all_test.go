package tool

import (
	"encoding/json"
	"testing"
)

func TestUserTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(tools))
	}
	wantNames := []string{
		"user-create-local",
		"user-get",
		"user-get-roles",
		"user-list",
		"user-search",
		"user-update-local",
		"user-delete-local",
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

func TestUserTools_WriteFlags(t *testing.T) {
	writeTools := map[string]bool{
		"user-create-local": true,
		"user-update-local": true,
		"user-delete-local": true,
	}
	for _, tl := range All() {
		wantWrite := writeTools[tl.Name]
		if tl.Writes != wantWrite {
			t.Errorf("tool %q: Writes = %v, want %v", tl.Name, tl.Writes, wantWrite)
		}
	}
}

func TestCreateLocalUser_Definition(t *testing.T) {
	tl := Create()
	if tl.Name != "user-create-local" {
		t.Errorf("name = %q", tl.Name)
	}
	if !tl.Writes {
		t.Error("Writes = false, want true")
	}
	if tl.Handler == nil {
		t.Error("nil handler")
	}
	if tl.InputSchema == nil {
		t.Error("nil input schema")
	}

	raw, err := json.Marshal(tl.InputSchema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("missing properties")
	}
	if _, has := props["password"]; has {
		t.Error("password must not be an input property")
	}
}
