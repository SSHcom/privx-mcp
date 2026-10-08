# SSH - PrivX MCP Server

An MCP (Model Context Protocol) server written in Go providing agents secure access to resources in a [PrivX](https://www.ssh.com/products/privileged-access-management-privx) instance.

Secure access starts with identity. The server runs in `oauth` or `m2m` (machine-to-machine) mode: an IdP token or a service secret is mapped to a PrivX user, and that user's roles decide which resources they can see, add, or update.

An [mcp proxy](docs/manual/reference/clients/privx-mcp-proxy.md) is also available for clients that have issues with streaming, OAuth, etc.

## Architecture

The MCP server uses the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). While other good libraries exist, we use the official SDK to more easily adapt to protocol changes. The server supports both stateless and session-based operation: it creates a session when a session ID is received, otherwise it runs stateless.

In both modes, tools run as the mapped PrivX user, and PrivX's audit log records that identity.

### `oauth` mode

The client signs in at an IdP; the server maps the token's identity claim to a PrivX user.

![](.md-images/oauth-mode.png)

### `m2m` mode

Machine-to-machine mode is for automated clients with no interactive sign-in. The client sends a service secret; the server maps that secret to one PrivX user.

![](.md-images/m2m-mode.png)

## Prerequisites

- Go 1.26.5+
- A PrivX instance with API Client and External Token Authentication configured
- Tested with PrivX v45, v44 & v43
- An RSA key pair (the public key registered in PrivX External Token configuration)
- For `oauth`: an IdP issuing OIDC tokens



## Security Precautions

The server fronts PrivX, a privileged access management platform. Anyone who can reach it and authenticate can act on PrivX resources with their mapped user's roles, so treat it with the same care as PrivX itself.

- **Limit access.** Only grant access to users who really need it, and keep their PrivX roles as narrow as possible.
- **Use HTTPS.** Serve TLS directly or put the server behind a TLS-terminating reverse proxy. Never expose plain HTTP outside a trusted host.
- **Choose client LLMs carefully.** Use good quality models that resist prompt injection and follow instructions reliably. If possible, use your own trained or self-hosted model.
- **Keep the server on the local network** where possible, rather than exposing it to the internet.
- **Use** `m2m` **mode only for automated access.** Interactive users should sign in through `oauth` mode so that actions are tied to their own identity.


## Sensitive data tools

Some tools can surface secrets or raw session content from PrivX. For example, `connection-trail-get` reconstructs the commands typed in a recorded SSH session, and keystroke-level input can include typed passwords, database connection strings, API tokens, and key material that never appeared on screen. These tools are treated as a distinct, higher-risk category.

They are **disabled by default** and are intentionally not listed in `privx-mcp-config-example.toml`. A server that does not set the flags below never registers them, so they cannot be listed or called.

> **Enable these tools only with a private, self-hosted LLM that you fully control.** Tool output is sent to whatever model the MCP client is wired to. With a third-party or hosted model, enabling these tools can send captured passwords and secrets outside your trust boundary. Do not enable them against a public or shared model endpoint.

To enable them, add to the `[permissions]` section of your `privx-mcp-config.toml` (or set the matching environment variables):

```toml
[permissions]
# Register sensitive-data tools. Default: false (tools are not registered).
enable_sensitive_data_tools = true

# Who may use them once enabled. Default: false = privx-admin role only.
# Set true to also allow non-admins who hold the tool's own PrivX permissions
# (for connection-trail-get: connections-view AND connections-trail).
sensitive_data_tools_allow_non_admin = true
```

Equivalent environment variables:

- `PERMISSIONS_ENABLE_SENSITIVE_DATA_TOOLS=true`
- `PERMISSIONS_SENSITIVE_DATA_TOOLS_ALLOW_NON_ADMIN=true`

Access model when enabled:

- With `sensitive_data_tools_allow_non_admin = false` (default), only users with the **privx-admin** role can see or call these tools.
- With `sensitive_data_tools_allow_non_admin = true`, the tool instead requires its own granular PrivX permissions. `connection-trail-get` requires both `connections-view` and `connections-trail`. privx-admin users always retain access.

These gates control whether a tool is exposed and to whom. They do not mask secrets within the tool output. The startup log records a warning whenever the gate is open, including which access mode is in effect.


## Documentation

- [Documents Hub](docs/README.md)
- [Manual](docs/manual/README.md)
- [Developer guide](docs/development/DEVELOPMENT.md)
- [Deployment](deploy/README.md)
  - Examples of how to deploy (Docker, Systemd)
  - Doing a local deployment (Docker + Keycloak) for evaluation purposes



## **Support & Commercial Services**

This is a public open-source project licensed under [Apache 2.0](LICENSE) and not covered by standard support SLA. Community feedback and contributions are welcome. Support is provided on a best-effort basis only. For dedicated support, customisations, or enterprise assistance, please raise a ticket via our support portal ([https://care.ssh.com](https://care.ssh.com)) or via your local support partner. Any requests would be assigned to your account manager.
