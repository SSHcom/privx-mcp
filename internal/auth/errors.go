package auth

// AuthError represents an authentication failure (as opposed to authorization,
// validation, or connectivity failures). It is matched by the MCP runtime's
// ToMCPError so that authenticator-side failures surface to the client as
// "authentication failed: …" rather than the generic unexpected-error message.
type AuthError struct {
	Message string
	Err     error
}

func (e *AuthError) Error() string { return e.Message }
func (e *AuthError) Unwrap() error { return e.Err }
