package registry

import (
	"context"
	"sync"
	"testing"
)

func dummyHandler(_ context.Context, _ map[string]any) (*ToolResult, error) {
	return &ToolResult{Content: []ContentBlock{{Type: "text", Text: "ok"}}}, nil
}

func TestNewRegistry_ReturnsEmptyRegistry(t *testing.T) {
	reg := NewRegistry()

	tools := reg.Tools()
	if len(tools) != 0 {
		t.Fatalf("expected empty registry, got %d tools", len(tools))
	}
}

func TestRegister_SingleTool(t *testing.T) {
	reg := NewRegistry()

	reg.Register(Tool{
		Name:        "test-tool",
		Description: "A test tool",
		Handler:     dummyHandler,
	})

	tools := reg.Tools()
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "test-tool" {
		t.Fatalf("expected tool name 'test-tool', got %q", tools[0].Name)
	}
}

func TestRegister_MultipleTools(t *testing.T) {
	reg := NewRegistry()

	reg.Register(
		Tool{Name: "tool-a", Description: "Tool A", Handler: dummyHandler},
		Tool{Name: "tool-b", Description: "Tool B", Handler: dummyHandler},
	)

	tools := reg.Tools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
}

func TestRegister_OverwritesSameName(t *testing.T) {
	reg := NewRegistry()

	reg.Register(Tool{Name: "tool-x", Description: "Original", Handler: dummyHandler})
	reg.Register(Tool{Name: "tool-x", Description: "Updated", Handler: dummyHandler})

	tools := reg.Tools()
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool after overwrite, got %d", len(tools))
	}
	if tools[0].Description != "Updated" {
		t.Fatalf("expected updated description, got %q", tools[0].Description)
	}
}

func TestGet_ExistingTool(t *testing.T) {
	reg := NewRegistry()

	reg.Register(Tool{Name: "find-me", Description: "Findable", Handler: dummyHandler})

	tool, ok := reg.Get("find-me")
	if !ok {
		t.Fatal("expected to find tool 'find-me'")
	}
	if tool.Name != "find-me" {
		t.Fatalf("expected tool name 'find-me', got %q", tool.Name)
	}
}

func TestGet_NonExistentTool(t *testing.T) {
	reg := NewRegistry()

	_, ok := reg.Get("missing")
	if ok {
		t.Fatal("expected tool 'missing' to not be found")
	}
}

func TestTools_ReturnsSnapshot(t *testing.T) {
	reg := NewRegistry()

	reg.Register(Tool{Name: "tool-1", Description: "First", Handler: dummyHandler})
	snapshot := reg.Tools()

	// Register another tool after taking the snapshot
	reg.Register(Tool{Name: "tool-2", Description: "Second", Handler: dummyHandler})

	// The snapshot should not reflect the new registration
	if len(snapshot) != 1 {
		t.Fatalf("snapshot should have 1 tool, got %d", len(snapshot))
	}
}

func TestTools_PreservesRegistrationOrder(t *testing.T) {
	reg := NewRegistry()

	reg.Register(Tool{Name: "charlie", Handler: dummyHandler})
	reg.Register(Tool{Name: "alpha", Handler: dummyHandler})
	reg.Register(Tool{Name: "bravo", Handler: dummyHandler})

	tools := reg.Tools()
	expected := []string{"charlie", "alpha", "bravo"}
	for i, name := range expected {
		if tools[i].Name != name {
			t.Fatalf("expected tools[%d].Name = %q, got %q", i, name, tools[i].Name)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			reg.Register(Tool{Name: "tool", Description: "concurrent", Handler: dummyHandler})
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = reg.Tools()
			_, _ = reg.Get("tool")
		}()
	}

	wg.Wait()

	// Should not panic and should have at least the tool registered
	_, ok := reg.Get("tool")
	if !ok {
		t.Fatal("expected tool to be registered after concurrent access")
	}
}
