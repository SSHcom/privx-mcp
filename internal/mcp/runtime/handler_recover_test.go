package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

func TestRecoverMiddleware_NoPanic(t *testing.T) {
	handler := func(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
		return &registry.ToolResult{
			Content: []registry.ContentBlock{{Type: "text", Text: "success"}},
			IsError: false,
		}, nil
	}

	wrapped := RecoverMiddleware(handler)
	result, err := wrapped(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("expected IsError to be false")
	}
	if resultText(result) != "success" {
		t.Fatalf("expected 'success', got %q", resultText(result))
	}
}

func TestRecoverMiddleware_PanicString(t *testing.T) {
	handler := func(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
		panic("something went wrong: secret_key=xyz")
	}

	wrapped := RecoverMiddleware(handler)
	result, err := wrapped(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertIsError(t, result)
	assertContains(t, resultText(result), "unexpected internal error")
	// Must NOT leak the panic message details.
	assertNotContains(t, resultText(result), "secret_key")
	assertNotContains(t, resultText(result), "xyz")
}

func TestRecoverMiddleware_PanicError(t *testing.T) {
	handler := func(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
		panic(errors.New("nil pointer dereference at auth.go:42"))
	}

	wrapped := RecoverMiddleware(handler)
	result, err := wrapped(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertIsError(t, result)
	assertContains(t, resultText(result), "unexpected internal error")
	// Must NOT expose stack trace details.
	assertNotContains(t, resultText(result), "nil pointer")
	assertNotContains(t, resultText(result), "auth.go")
}

func TestRecoverMiddleware_PanicInt(t *testing.T) {
	handler := func(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
		panic(42)
	}

	wrapped := RecoverMiddleware(handler)
	result, err := wrapped(context.Background(), nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertIsError(t, result)
	assertContains(t, resultText(result), "unexpected internal error")
}

func TestRecoverMiddleware_HandlerReturnsError(t *testing.T) {
	handler := func(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
		return nil, &ValidationError{Message: "bad params", Fields: []string{"offset"}}
	}

	wrapped := RecoverMiddleware(handler)
	_, err := wrapped(context.Background(), nil)

	// RecoverMiddleware should pass through regular errors.
	if err == nil {
		t.Fatal("expected error to be passed through")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatal("expected ValidationError to pass through")
	}
}
