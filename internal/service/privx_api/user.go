package api

import (
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
)

const roleStoreSearchUsersPageLimit = 100

// UserRef is a minimal user reference returned by user lookups.
type UserRef struct {
	ID          string
	DisplayName string
}

// UserService wraps user-related PrivX API operations.
type UserService struct {
	roleStore *rolestore.RoleStore
}

// NewUserService creates a user API service for PrivX requests.
func NewUserService(client restapi.Connector) *UserService {
	if client == nil {
		return &UserService{}
	}

	return &UserService{
		roleStore: rolestore.New(client),
	}
}

// SearchAllUsers fetches all users using paged role-store search.
func (s *UserService) SearchAllUsers(search rolestore.UserSearch) ([]rolestore.User, error) {
	if s == nil || s.roleStore == nil {
		return nil, nil
	}

	users := make([]rolestore.User, 0)
	offset := 0

	for {
		page, err := s.roleStore.SearchUsers(
			search,
			filters.Limit(roleStoreSearchUsersPageLimit),
			filters.Offset(offset),
		)
		if err != nil {
			return nil, err
		}

		if page == nil || len(page.Items) == 0 {
			break
		}

		users = append(users, page.Items...)
		offset += len(page.Items)

		if !hasMoreUsers(page, offset) {
			break
		}
	}

	return users, nil
}

// ResolveUser resolves a user identifier (UUID or search keyword) to a UserRef.
//
// UUID-shaped strings are fetched via GetUser. Other strings are searched with
// keywords; exact matches on principal, full_name, or email are preferred, and
// exactly one unique user must remain or the call fails as ambiguous/unresolved.
func (s *UserService) ResolveUser(identifier string) (UserRef, error) {
	if s == nil || s.roleStore == nil {
		return UserRef{}, fmt.Errorf("user service is not initialized")
	}

	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return UserRef{}, fmt.Errorf("user identifier is empty")
	}

	if roleIDRe.MatchString(identifier) {
		user, err := s.roleStore.GetUser(identifier)
		if err != nil {
			return UserRef{}, fmt.Errorf("user id %q: %w", identifier, err)
		}

		return userRefFromUser(user), nil
	}

	users, err := s.SearchAllUsers(rolestore.UserSearch{Keywords: identifier})
	if err != nil {
		return UserRef{}, fmt.Errorf("search users %q: %w", identifier, err)
	}

	if len(users) == 0 {
		return UserRef{}, fmt.Errorf("user %q did not resolve to any user", identifier)
	}

	exact := make([]rolestore.User, 0)

	for _, u := range users {
		if userMatchesIdentifier(u, identifier) {
			exact = append(exact, u)
		}
	}

	candidates := exact
	if len(candidates) == 0 {
		candidates = users
	}

	unique := uniqueUsersByID(candidates)
	if len(unique) == 1 {
		return userRefFromUser(&unique[0]), nil
	}

	return UserRef{}, fmt.Errorf("user %q is ambiguous (matches %d users)", identifier, len(unique))
}

// ResolveUserRoles resolves effective permissions for one user.
func (s *UserService) ResolveUserRoles(userID string) (*rolestore.User, error) {
	if s == nil || s.roleStore == nil {
		return nil, nil
	}

	return s.roleStore.ResolveUserRoles(userID)
}

func userRefFromUser(user *rolestore.User) UserRef {
	if user == nil {
		return UserRef{}
	}

	name := user.FullName
	if name == "" {
		name = user.Principal
	}

	return UserRef{ID: user.ID, DisplayName: name}
}

func userMatchesIdentifier(user rolestore.User, identifier string) bool {
	return strings.EqualFold(user.Principal, identifier) ||
		strings.EqualFold(user.FullName, identifier) ||
		strings.EqualFold(user.Email, identifier)
}

func uniqueUsersByID(users []rolestore.User) []rolestore.User {
	seen := make(map[string]struct{}, len(users))

	out := make([]rolestore.User, 0, len(users))
	for _, u := range users {
		if u.ID == "" {
			continue
		}

		if _, ok := seen[u.ID]; ok {
			continue
		}

		seen[u.ID] = struct{}{}
		out = append(out, u)
	}

	return out
}

func hasMoreUsers(page *response.ResultSet[rolestore.User], fetched int) bool {
	if page == nil {
		return false
	}

	if page.Count > 0 {
		return fetched < page.Count
	}

	return len(page.Items) == roleStoreSearchUsersPageLimit
}
