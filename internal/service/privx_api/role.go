package api

import (
	"fmt"
	"regexp"

	"github.com/SSHcom/privx-sdk-go/v2/api/rolestore"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
)

// roleIDRe matches canonical UUID strings, used to tell role IDs apart from
// role names in mixed identifier inputs.
var roleIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// RoleRef is a minimal role reference (id + name) returned by role lookups.
// It decouples callers from the rolestore SDK type.
type RoleRef struct {
	ID   string
	Name string
}

// RoleService wraps role-related PrivX API operations.
type RoleService struct {
	roleStore *rolestore.RoleStore
}

// NewRoleService creates a role API service for PrivX requests. A nil client
// produces an uninitialized service whose methods return an error rather than
// silently no-op'ing, since role resolution feeds write operations where
// silent failures would corrupt data.
func NewRoleService(client restapi.Connector) *RoleService {
	if client == nil {
		return &RoleService{}
	}

	return &RoleService{roleStore: rolestore.New(client)}
}

// ResolveRoles resolves a slice of role identifiers (role names or role UUIDs)
// into RoleRef objects, returning a cache keyed by the original input string.
//
// Names are resolved in a single batch via the role-store resolve endpoint;
// each name must resolve to exactly one role (duplicate names mapping to
// different ids are rejected as ambiguous, and unresolved names error out).
// UUIDs are resolved individually via GetRole. Duplicate identifiers in the
// input are resolved only once.
func (s *RoleService) ResolveRoles(identifiers []string) (map[string]RoleRef, error) {
	if s == nil || s.roleStore == nil {
		return nil, fmt.Errorf("role service is not initialized")
	}

	cache := make(map[string]RoleRef, len(identifiers))

	var names []string

	for _, id := range identifiers {
		if _, seen := cache[id]; seen {
			continue
		}

		if roleIDRe.MatchString(id) {
			role, err := s.roleStore.GetRole(id)
			if err != nil {
				return nil, fmt.Errorf("role id %q: %w", id, err)
			}

			cache[id] = RoleRef{ID: role.ID, Name: role.Name}
		} else {
			names = append(names, id)
		}
	}

	if len(names) > 0 {
		resolved, err := s.roleStore.ResolveRoles(names)
		if err != nil {
			return nil, fmt.Errorf("resolve role names: %w", err)
		}

		byName := make(map[string]*rolestore.Role, len(resolved.Items))
		for i := range resolved.Items {
			role := &resolved.Items[i]
			if existing, ok := byName[role.Name]; ok && existing.ID != role.ID {
				return nil, fmt.Errorf("role name %q is ambiguous (matches multiple role ids)", role.Name)
			}

			byName[role.Name] = role
		}

		for _, name := range names {
			role, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("role name %q did not resolve to any role", name)
			}

			cache[name] = RoleRef{ID: role.ID, Name: role.Name}
		}
	}

	return cache, nil
}
