# PrivX MCP documentation

Documentation has been split into four parts:

1. Guide – A guided reading path of the installation and configuration
2. Reference - In-dept instructions and descriptions (the guide will link to these)
3. Development - Development HowTos
4. Diagrams - Architectural diagrams (Browser based)

## Guide

1. [Connect to an already running server](guide/01-connect.md)
2. [Installation](guide/02-install.md)
3. [Configure the server](guide/03-configure.md)
4. Choose one auth path:
   - [Configure OIDC](guide/04-oidc.md) (Keycloak, Microsoft Entra ID, or Okta)
   - [Configure machine-to-machine access](guide/04-m2m/04-m2m.md)
5. [Security and user operations](guide/05-security-and-usage.md)

## Reference

Supporting documentation, grouped by topic. The guide points into these pages.

- Server
  - [MCP server configuration](reference/server/SERVER.md)
  - [Configure machine-to-machine access](guide/04-m2m/04-m2m.md)
  - [PrivX configuration](reference/server/privx.md)
  - [TLS (HTTPS)](reference/server/tls.md)

- OIDC
  - [OIDC configuration](reference/oidc/OIDC.md)
  - [Keycloak](reference/oidc/keycloak.md)
  - [Microsoft Entra ID](reference/oidc/entra-id/ENTRA-ID.md)
  - [Entra auth flow diagram](reference/oidc/entra-id/auth-flow.md)
  - [Okta](reference/oidc/okta.md), including federation to Microsoft Entra ID

- Clients
  - [MCP client configuration](reference/clients/CLIENTS.md)
  - [privx-mcp-proxy](reference/clients/privx-mcp-proxy.md)

- Security
  - [Security considerations](reference/security/security.md)
  - [User-level security](reference/security/user_level_security.md)
  - [Redacted fields](reference/security/redacted_fields.md)

- User
  - [User documentation](reference/user/USER.md)
  - [MCP tools](reference/user/tools.md)

## Development

- [Development](development/DEVELOPMENT.md)

## Diagrams

- [Diagrams](diagrams/)
