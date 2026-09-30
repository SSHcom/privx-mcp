package devtools

import (
	"context"
	"strings"
	"testing"
)

func TestTestTools(t *testing.T) {
	tools := TestTools()
	if len(tools) != 1 {
		t.Fatalf("TestTools() returned %d tools, want 1", len(tools))
	}
	if tools[0].Name != "echo" {
		t.Errorf("name = %q, want echo", tools[0].Name)
	}
	if tools[0].Writes {
		t.Error("Writes = true, want false")
	}
	if tools[0].Handler == nil {
		t.Error("nil handler")
	}
	if tools[0].InputSchema == nil {
		t.Error("nil input schema")
	}
}

func TestEchoHandler_Happy(t *testing.T) {
	res, err := echoHandler(context.Background(), map[string]any{"message": "hello"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	if !strings.Contains(res.Content[0].Text, `"echo":"dummy: hello"`) {
		t.Errorf("got %q", res.Content[0].Text)
	}
}

func TestEchoHandler_MissingMessage(t *testing.T) {
	res, err := echoHandler(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "message is required") {
		t.Errorf("got %q", res.Content[0].Text)
	}
}
