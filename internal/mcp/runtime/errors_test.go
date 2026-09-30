package runtime

import (
	"errors"
	"fmt"
	"testing"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/privx"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

func TestToMCPError_Nil(t *testing.T) {
	result := ToMCPError(nil)
	if result != nil {
		t.Fatal("expected nil result for nil error")
	}
}

func TestToMCPError_ValidationError(t *testing.T) {
	err := &ValidationError{
		Message: "missing required fields",
		Fields:  []string{"commonName", "addresses"},
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "commonName")
	assertContains(t, resultText(result), "addresses")
}

func TestToMCPError_ValidationErrorNoFields(t *testing.T) {
	err := &ValidationError{
		Message: "offset must be non-negative",
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "offset must be non-negative")
}

func TestToMCPError_AuthorizationError(t *testing.T) {
	err := &AuthorizationError{
		ToolName: "host-create",
		Message:  "not authorized to invoke host-create",
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "not authorized to invoke host-create")
}

func TestToMCPError_AuthError(t *testing.T) {
	err := &auth.AuthError{
		Message: "token expired",
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "authentication failed")
	// Must NOT contain internal details like tokens or keys.
	assertNotContains(t, resultText(result), "token expired")
}

func TestToMCPError_VerificationError(t *testing.T) {
	err := &oauth.VerificationError{
		Reason:  "expired",
		Message: "token has expired",
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "authentication failed: token has expired")
}

func TestToMCPError_ExchangeAuthError(t *testing.T) {
	err := &privx.ExchangeAuthError{
		Message: "PrivX rejected the user identity: 401 unauthorized",
		Err:     errors.New("401"),
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "authentication failed")
	assertContains(t, resultText(result), "PrivX rejected the user identity")
}

func TestToMCPError_APIError(t *testing.T) {
	err := &APIError{
		Message:    "host not found",
		StatusCode: 404,
		Body:       "host with id xyz not found",
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "404")
	assertContains(t, resultText(result), "host with id xyz not found")
}

func TestToMCPError_NetworkError(t *testing.T) {
	err := &NetworkError{
		Message: "connection refused",
		Err:     errors.New("dial tcp: connection refused"),
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "connectivity failure")
	// Must NOT leak internal network details.
	assertNotContains(t, resultText(result), "dial tcp")
}

func TestToMCPError_AuthNetworkError(t *testing.T) {
	err := &privx.NetworkError{
		Message: "connectivity problem reaching PrivX at https://privx.example.com",
		Err:     errors.New("dial tcp: i/o timeout"),
	}
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "connectivity failure")
	// Must NOT leak internal URL or network details.
	assertNotContains(t, resultText(result), "privx.example.com")
	assertNotContains(t, resultText(result), "i/o timeout")
}

func TestToMCPError_UnknownError(t *testing.T) {
	err := errors.New("some internal secret: key=abc123")
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "unexpected error")
	// Must NOT leak the internal error message.
	assertNotContains(t, resultText(result), "secret")
	assertNotContains(t, resultText(result), "abc123")
}

func TestToMCPError_WrappedValidationError(t *testing.T) {
	inner := &ValidationError{
		Message: "bad input",
		Fields:  []string{"limit"},
	}
	err := fmt.Errorf("tool execution: %w", inner)
	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "limit")
}

func TestToMCPError_NestedTypedErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    string
		notWant string
	}{
		{
			name:    "generic wrapped twice",
			err:     fmt.Errorf("failed to create access request: %w", fmt.Errorf("privx: %w", errors.New("boom"))),
			want:    "unexpected error",
			notWant: "boom",
		},
		{
			name: "validation wrapped twice",
			err: fmt.Errorf("handler: %w", fmt.Errorf("parse params: %w", &ValidationError{
				Message: "bad input",
				Fields:  []string{"limit"},
			})),
			want: "limit",
		},
		{
			name: "API error from handler wrap",
			err: fmt.Errorf("failed to create access request: %w", &APIError{
				Message:    "unavailable",
				StatusCode: 503,
				Body:       "service unavailable",
			}),
			want: "503",
		},
		{
			name: "API error wrapped twice",
			err: fmt.Errorf("tool: %w", fmt.Errorf("privx call: %w", &APIError{
				Message:    "host not found",
				StatusCode: 404,
				Body:       "host with id xyz not found",
			})),
			want: "host with id xyz not found",
		},
		{
			name: "network error wrapped twice",
			err: fmt.Errorf("tool: %w", fmt.Errorf("dial: %w", &NetworkError{
				Message: "connection refused",
				Err:     errors.New("dial tcp: connection refused"),
			})),
			want:    "connectivity failure",
			notWant: "dial tcp",
		},
		{
			name: "authorization wrapped twice",
			err: fmt.Errorf("middleware: %w", fmt.Errorf("scope: %w", &AuthorizationError{
				ToolName: "host-create",
			})),
			want: "not authorized to invoke host-create",
		},
		{
			name: "auth error wrapped twice",
			err: fmt.Errorf("exchange: %w", fmt.Errorf("verify: %w", &auth.AuthError{
				Message: "token expired",
			})),
			want:    "authentication failed",
			notWant: "token expired",
		},
		{
			name: "verification error wrapped twice",
			err: fmt.Errorf("auth: %w", fmt.Errorf("jwt: %w", &oauth.VerificationError{
				Reason:  "expired",
				Message: "token has expired",
			})),
			want: "authentication failed: token has expired",
		},
		{
			name: "exchange auth error wrapped twice",
			err: fmt.Errorf("connect: %w", fmt.Errorf("token: %w", &privx.ExchangeAuthError{
				Message: "PrivX rejected the user identity: 401 unauthorized",
				Err:     errors.New("401"),
			})),
			want: "PrivX rejected the user identity",
		},
		{
			name: "privx network error wrapped twice",
			err: fmt.Errorf("connect: %w", fmt.Errorf("http: %w", &privx.NetworkError{
				Message: "connectivity problem reaching PrivX at https://privx.example.com",
				Err:     errors.New("dial tcp: i/o timeout"),
			})),
			want:    "connectivity failure",
			notWant: "privx.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToMCPError(tt.err)
			assertIsError(t, result)
			assertContains(t, resultText(result), tt.want)
			if tt.notWant != "" {
				assertNotContains(t, resultText(result), tt.notWant)
			}
		})
	}
}

func TestToMCPError_PercentVDropsTypedCause(t *testing.T) {
	inner := &ValidationError{
		Message: "bad input",
		Fields:  []string{"limit"},
	}
	// %v stringifies the typed error and drops Unwrap, so classification
	// cannot see ValidationError. Session 1 converted production wrappers to
	// %w; this test locks that requirement in.
	err := fmt.Errorf("tool execution: %v", inner) //nolint:errorlint // intentional non-wrapping verb

	result := ToMCPError(err)

	assertIsError(t, result)
	assertContains(t, resultText(result), "unexpected error")
	assertNotContains(t, resultText(result), "limit")
}

// --- Test helpers ---

func assertIsError(t *testing.T, result *registry.ToolResult) {
	t.Helper()
	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}
	if !result.IsError {
		t.Fatal("expected IsError to be true")
	}
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !contains(s, substr) {
		t.Fatalf("expected %q to contain %q", s, substr)
	}
}

func assertNotContains(t *testing.T, s, substr string) {
	t.Helper()
	if contains(s, substr) {
		t.Fatalf("expected %q to NOT contain %q", s, substr)
	}
}

func contains(s, substr string) bool {
	return substr != "" && len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func resultText(result *registry.ToolResult) string {
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	return result.Content[0].Text
}
