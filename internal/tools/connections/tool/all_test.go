package tool

import "testing"

func TestConnectionsTools_Registration(t *testing.T) {
	tools := All()
	if len(tools) != 5 {
		t.Fatalf("expected 5 tools, got %d", len(tools))
	}
	wantNames := []string{
		"connection-get", "connection-list",
		"connection-search", "connection-trail-get",
		"connection-terminate",
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

func TestConnectionsTools_TrailGetIsSensitive(t *testing.T) {
	for _, tl := range All() {
		if tl.Name == "connection-trail-get" {
			if !tl.Sensitive {
				t.Fatal("connection-trail-get must be marked Sensitive")
			}

			return
		}
	}

	t.Fatal("connection-trail-get not found")
}

func TestConnectionsTools_WriteFlags(t *testing.T) {
	tools := All()
	writeTools := map[string]bool{
		"connection-list":      false,
		"connection-get":       false,
		"connection-search":    false,
		"connection-trail-get": false,
		"connection-terminate": true,
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
