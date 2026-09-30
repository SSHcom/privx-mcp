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
}

// ResolvePrincipals converts MCP principal objects into hoststore principals,
// resolving role names and UUIDs through the role store.
func ResolvePrincipals(raw []any, connector restapi.Connector) ([]hoststore.HostPrincipals, error) {
	parsed := make([]principalRoles, 0, len(raw))
	allRoles := make([]string, 0)

	for i, item := range raw {
		p, roles, err := ToPrincipalInput(item)
		if err != nil {
			return nil, fmt.Errorf("validation error: principals[%d]: %w", i, err)
		}

		parsed = append(parsed, principalRoles{principal: p, roles: roles})
		allRoles = append(allRoles, roles...)
	}

	roleCache, err := apiservice.NewRoleService(connector).ResolveRoles(allRoles)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve roles: %w", err)
	}

	principals := make([]hoststore.HostPrincipals, 0, len(parsed))
	for _, pp := range parsed {
		roles := make([]hoststore.HostRole, 0, len(pp.roles))
		for _, r := range pp.roles {
			ref, ok := roleCache[r]
			if !ok {
				return nil, fmt.Errorf("internal error: role %q missing from resolved cache", r)
			}

			roles = append(roles, hoststore.HostRole{ID: ref.ID, Name: ref.Name})
		}

		principals = append(principals, hoststore.HostPrincipals{
			Principal: pp.principal,
			Roles:     roles,
		})
	}

	return principals, nil
}
