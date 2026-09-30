package auth

import (
	"context"

	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// contextKey is an unexported type used for context value keys to avoid collisions.
type contextKey struct{}

// authContextKey is the context key for storing AuthContext.
var authContextKey = contextKey{}

// Role is an active PrivX role membership for a tool call.
type Role struct {
	ID   string
	Name string
}

// AuthContext holds the authenticated user state for a single tool call.
type AuthContext struct {
	Username  string            // Mapped PrivX username
	UserID    string            // Resolved PrivX user ID (empty if resolve failed)
	Roles     []Role            // Active PrivX roles for this call
	Connector restapi.Connector // Authenticated SDK connector
}

// NewContext returns a new context with the given AuthContext stored as a value.
func NewContext(ctx context.Context, ac *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, ac)
}

// FromContext retrieves the AuthContext from the context.
// Returns nil if no AuthContext is present.
func FromContext(ctx context.Context) *AuthContext {
	ac, _ := ctx.Value(authContextKey).(*AuthContext)
	return ac
}

// HasRole reports whether the caller currently has the given PrivX role.
// When id is provided and non-empty, membership is matched by role ID.
// Otherwise the role name is matched case-insensitively with surrounding
// whitespace trimmed. Pass an empty name with an id to check by ID only.
func (ac *AuthContext) HasRole(name string, id ...string) bool {
	if ac == nil {
		return false
	}

	roleID := ""
	if len(id) > 0 {
		roleID = id[0]
	}

	if roleID != "" {
		for _, role := range ac.Roles {
			if utils.EqualFoldTrimmed(role.ID, roleID) {
				return true
			}
		}

		return false
	}

	if name == "" {
		return false
	}

	for _, role := range ac.Roles {
		if utils.EqualFoldTrimmed(role.Name, name) {
			return true
		}
	}

	return false
}

// HasAnyRole reports whether the caller currently has at least one of the
// given PrivX role names.
func (ac *AuthContext) HasAnyRole(roles ...string) bool {
	if ac == nil {
		return false
	}

	for _, role := range roles {
		if ac.HasRole(role) {
			return true
		}
	}

	return false
}
