package privx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	sdkoauth "github.com/SSHcom/privx-sdk-go/v2/oauth"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// TokenExchanger exchanges a minted JWT for an authenticated PrivX SDK connector.
type TokenExchanger interface {
	Exchange(ctx context.Context, mintedJWT string) (restapi.Connector, error)
}

// NetworkError represents a network-level failure communicating with PrivX.
type NetworkError struct {
	Message string
	Err     error
}

func (e *NetworkError) Error() string {
	return e.Message
}

func (e *NetworkError) Unwrap() error {
	return e.Err
}

// ExchangeAuthError represents an authentication failure during token exchange (401/403).
type ExchangeAuthError struct {
	Message string
	Err     error
}

func (e *ExchangeAuthError) Error() string {
	return e.Message
}

func (e *ExchangeAuthError) Unwrap() error {
	return e.Err
}

// ExchangerConfig holds the configuration for creating a PrivXTokenExchanger.
type ExchangerConfig struct {
	PrivXBaseURL string
}

// PrivXTokenExchanger implements TokenExchanger using the privx-sdk-go OAuth mechanism.
type PrivXTokenExchanger struct {
	baseURL string
}

// NewPrivXTokenExchanger creates a new token exchanger for the given PrivX instance.
func NewPrivXTokenExchanger(cfg ExchangerConfig) (*PrivXTokenExchanger, error) {
	if cfg.PrivXBaseURL == "" {
		return nil, fmt.Errorf("PrivX base URL is required")
	}

	return &PrivXTokenExchanger{
		baseURL: strings.TrimRight(cfg.PrivXBaseURL, "/"),
	}, nil
}

// Exchange takes a minted JWT string and creates a new authenticated PrivX connector.
// A new connector is created per call (no token caching).
func (e *PrivXTokenExchanger) Exchange(_ context.Context, mintedJWT string) (restapi.Connector, error) {
	logging.Debug("token exchange", "url", e.baseURL+"/auth/api/v1/token/login")

	// Create a base connector for the token exchange request.
	baseClient := restapi.New(
		restapi.BaseURL(e.baseURL),
	)

	// Build OAuth options for the exchange.
	opts := []sdkoauth.Option{
		sdkoauth.ExchangeToken(mintedJWT),
	}

	// Create the authorizer that will perform the token exchange.
	authorizer := sdkoauth.WithExchangeToken(baseClient, opts...)

	// Eagerly obtain the access token to detect errors immediately.
	_, err := authorizer.AccessToken()
	if err != nil {
		classified := e.classifyError(err)
		logging.Error(
			"token exchange failed",
			"raw_error", err.Error(),
			"classified_error", classified,
		)

		return nil, classified
	}

	logging.Debug("token exchange succeeded")

	// Create the authenticated connector using the authorizer.
	connector := restapi.New(
		restapi.BaseURL(e.baseURL),
		restapi.Auth(authorizer),
	)

	return connector, nil
}

// classifyError distinguishes authentication errors (401/403) from network errors.
func (e *PrivXTokenExchanger) classifyError(err error) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Check for authentication rejection (401/403 style errors from PrivX).
	if isAuthRejection(errMsg) {
		return &ExchangeAuthError{
			Message: fmt.Sprintf("PrivX rejected the user identity: %s", errMsg),
			Err:     err,
		}
	}

	// The SDK retries on 401 responses until the retry limit is reached.
	// When this happens, the error can be "request failed after N tries" or
	// a body-consumed pattern. Check before network errors since *url.Error
	// also satisfies net.Error.
	if isSDKRetryExhausted(errMsg) {
		return &ExchangeAuthError{
			Message: fmt.Sprintf("PrivX rejected the user identity: %s", errMsg),
			Err:     err,
		}
	}

	// Check for network-level errors (timeouts, DNS failures, connection refused).
	if isNetworkError(err) {
		return &NetworkError{
			Message: fmt.Sprintf("connectivity problem reaching PrivX at %s: %s", e.baseURL, errMsg),
			Err:     err,
		}
	}

	// Default: wrap as a network error for any other failure.
	return &NetworkError{
		Message: fmt.Sprintf("token exchange failed: %s", errMsg),
		Err:     err,
	}
}

// isNetworkError checks if the error is a network-level failure.
func isNetworkError(err error) bool {
	// Check for net.Error (timeouts, DNS, connection refused)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// Check for common network error patterns in the error string.
	msg := err.Error()

	networkPatterns := []string{
		"connection refused",
		"no such host",
		"dial tcp",
		"i/o timeout",
		"network is unreachable",
		"TLS handshake timeout",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isAuthRejection checks if the error message indicates an auth rejection (401/403).
func isAuthRejection(errMsg string) bool {
	lower := strings.ToLower(errMsg)

	authPatterns := []string{
		"401",
		"403",
		"unauthorized",
		"forbidden",
		"authentication failed",
		"access denied",
		"invalid_grant",
		// SDK ErrorFromResponse format: "error: <code>" or "error: " (empty code)
		// and "HTTP error: <status>" (empty body or parse failure).
		// These always originate from a PrivX HTTP error response, never from
		// a network-level failure, so they are auth/server rejections.
		"error: ",
		"http error:",
	}
	for _, pattern := range authPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// isSDKRetryExhausted checks if the error is a "request failed after N tries" from the SDK,
// which happens when the SDK retries on 401 until the retry limit is reached.
// Also catches the body-consumed pattern where the SDK retries a POST with a spent body buffer.
func isSDKRetryExhausted(errMsg string) bool {
	if strings.Contains(errMsg, "request failed after") && strings.Contains(errMsg, "tries") {
		return true
	}
	// When the SDK retries on 401, the POST body buffer is consumed. The second
	// attempt then fails with a content-length mismatch. This only occurs after
	// the initial 401, so it indicates auth rejection.
	if strings.Contains(errMsg, "ContentLength") && strings.Contains(errMsg, "Body length 0") {
		return true
	}

	return false
}
