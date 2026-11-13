package hosts

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	apiservice "github.com/pmsshintegration/privx-mcp/internal/service/privx_api"
)

type principalRoles struct {
	principal string
	roles     []string

	// serviceOptions is the raw service_options object, set only when the
	// caller supplied the key.
	serviceOptions    any
	hasServiceOptions bool
}

// ResolvePrincipals converts MCP principal objects into hoststore principals,
// resolving role names and UUIDs through the role store.
//
// stored is the host's current principals on update, or nil on create. A
// principal that supplies service_options has them applied on top of the stored
// principal with the same name, so fields it omits keep their stored values.
// With no stored options, omitted SSH fields default to enabled and omitted
// fields of other protocols to false or 0. A principal that
// omits service_options leaves the field nil here; update then keeps the stored
// value (see preserveStoredPrincipalFields) and create leaves it to PrivX.
func ResolvePrincipals(raw []any, connector restapi.Connector, stored []hoststore.HostPrincipals) ([]hoststore.HostPrincipals, error) {
	parsed := make([]principalRoles, 0, len(raw))
	allRoles := make([]string, 0)

	for i, item := range raw {
		p, roles, err := ToPrincipalInput(item)
		if err != nil {
			return nil, fmt.Errorf("validation error: principals[%d]: %w", i, err)
		}

		pp := principalRoles{principal: p, roles: roles}

		if m, ok := item.(map[string]any); ok {
			if so, has := m["service_options"]; has {
				// Validate the shape now, before any role lookup.
				if _, err := ApplyServiceOptions(nil, so); err != nil {
					return nil, fmt.Errorf("validation error: principals[%d]: service_options: %w", i, err)
				}

				pp.serviceOptions, pp.hasServiceOptions = so, true
			}
		}

		parsed = append(parsed, pp)
		allRoles = append(allRoles, roles...)
	}

	roleCache, err := apiservice.NewRoleService(connector).ResolveRoles(allRoles)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve roles: %w", err)
	}

	principals := make([]hoststore.HostPrincipals, 0, len(parsed))
	usedStored := make(map[int]struct{}, len(stored))

	for i, pp := range parsed {
		roles := make([]hoststore.HostRole, 0, len(pp.roles))
		for _, r := range pp.roles {
			ref, ok := roleCache[r]
			if !ok {
				return nil, fmt.Errorf("internal error: role %q missing from resolved cache", r)
			}

			roles = append(roles, hoststore.HostRole{ID: ref.ID, Name: ref.Name})
		}

		principal := hoststore.HostPrincipals{
			Principal: pp.principal,
			Roles:     roles,
		}

		// Pair with a stored principal the same way preserveStoredPrincipalFields
		// does (in order, each stored entry used once) so both agree.
		src := matchStoredPrincipal(stored, usedStored, pp.principal)
		if src >= 0 {
			usedStored[src] = struct{}{}
		}

		if pp.hasServiceOptions {
			var base *hoststore.HostServiceOptions
			if src >= 0 {
				base = stored[src].ServiceOptions
			}

			so, err := ApplyServiceOptions(base, pp.serviceOptions)
			if err != nil {
				return nil, fmt.Errorf("validation error: principals[%d]: service_options: %w", i, err)
			}

			principal.ServiceOptions = so
		}

		principals = append(principals, principal)
	}

	return principals, nil
}

// preserveStoredPrincipalFields copies account settings that host-update does
// not accept from stored principals onto replacements with the same principal
// name. Roles and the name come from the replacement, and so do service
// options when the replacement supplied them. Each stored principal
// is used at most once, in order, so duplicate names stay paired with the
// account they already belonged to. A name that is not already on the host
// starts without those settings.
func preserveStoredPrincipalFields(stored, next []hoststore.HostPrincipals) {
	if len(stored) == 0 || len(next) == 0 {
		return
	}

	used := make(map[int]struct{}, len(stored))
	for i := range next {
		src := matchStoredPrincipal(stored, used, next[i].Principal)
		if src < 0 {
			continue
		}

		used[src] = struct{}{}
		copyStoredPrincipalFields(&next[i], stored[src])
	}
}

func matchStoredPrincipal(stored []hoststore.HostPrincipals, used map[int]struct{}, name string) int {
	for i := range stored {
		if _, ok := used[i]; ok {
			continue
		}

		if stored[i].Principal == name {
			return i
		}
	}

	return -1
}

func copyStoredPrincipalFields(dst *hoststore.HostPrincipals, src hoststore.HostPrincipals) {
	dst.TargetDomain = src.TargetDomain
	dst.Passphrase = src.Passphrase
	dst.Rotate = src.Rotate
	dst.UseForPasswordRotation = src.UseForPasswordRotation
	dst.UsernameAttribute = src.UsernameAttribute
	dst.UseUserAccount = src.UseUserAccount
	dst.Source = src.Source
	dst.Applications = src.Applications
	// Service options supplied with the replacement win; they were already
	// overlaid on the stored value by ResolvePrincipals.
	if dst.ServiceOptions == nil {
		dst.ServiceOptions = src.ServiceOptions
	}

	dst.CommandRestrictions = src.CommandRestrictions
}
