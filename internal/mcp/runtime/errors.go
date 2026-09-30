package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/auth/privx"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
)

// ValidationError reports invalid tool input; it maps to a client-visible
// validation message.
type ValidationError struct {
	Message string
	Fields  []string
}

func (e *ValidationError) Error() string {
	if len(e.Fields) > 0 {
		return fmt.Sprintf("%s: %s", e.Message, strings.Join(e.Fields, ", "))
	}

	return e.Message
}

// APIError reports a failed PrivX API call together with its HTTP status.
type APIError struct {
	Message    string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("PrivX API error (HTTP %d): %s", e.StatusCode, e.Message)
}

// NetworkError reports a connectivity failure while reaching PrivX.
type NetworkError struct {
	Message string
	Err     error
}

func (e *NetworkError) Error() string { return e.Message }
func (e *NetworkError) Unwrap() error { return e.Err }

// AuthorizationError reports that the caller may not invoke a tool.
type AuthorizationError struct {
	ToolName string
	Message  string
}

func (e *AuthorizationError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return fmt.Sprintf("not authorized to invoke %s", e.ToolName)
}

// ToMCPError classifies a handler error and renders it as a redacted tool
// result. Unrecognized errors become a generic message.
func ToMCPError(err error) *registry.ToolResult {
	if err == nil {
		return nil
	}

	var (
		msg             string
		authErr         *auth.AuthError
		validationErr   *ValidationError
		apiErr          *APIError
		networkErr      *NetworkError
		authzErr        *AuthorizationError
		exchangeAuthErr *privx.ExchangeAuthError
		authNetworkErr  *privx.NetworkError
		verifErr        *oauth.VerificationError
	)

	switch {
	case errors.As(err, &verifErr):
		msg = fmt.Sprintf("authentication failed: %s", verifErr.Message)
	case errors.As(err, &validationErr):
		if len(validationErr.Fields) > 0 {
			msg = fmt.Sprintf("invalid input: missing or invalid fields: %s", strings.Join(validationErr.Fields, ", "))
		} else {
			msg = fmt.Sprintf("invalid input: %s", validationErr.Message)
		}
	case errors.As(err, &authzErr):
		msg = fmt.Sprintf("not authorized to invoke %s", authzErr.ToolName)
	case errors.As(err, &authErr):
		msg = "authentication failed"
	case errors.As(err, &exchangeAuthErr):
		msg = "authentication failed: PrivX rejected the user identity"
	case errors.As(err, &apiErr):
		msg = fmt.Sprintf("PrivX API error (HTTP %d): %s", apiErr.StatusCode, apiErr.Body)
	case errors.As(err, &networkErr):
		msg = "connectivity failure: unable to reach PrivX"
	case errors.As(err, &authNetworkErr):
		msg = "connectivity failure: unable to reach PrivX"
	default:
		msg = "an unexpected error occurred"
	}

	return &registry.ToolResult{
		Content: []registry.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
