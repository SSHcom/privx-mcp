# Configure the server

Create a `privx-mcp-config.toml` file that configures the server.

## 1) Start from the example file

Create `privx-mcp-config.toml`. In the GitHub repository, find `privx-mcp-config-example.toml` at the repository root, then copy its contents and paste them into the new file. The example file carries the full schema.

## 2) Fill the minimum required settings

The server opens two separate connections to PrivX, and each needs its own setup in PrivX:

- **API client connection** (server-level): opened once at startup with the `[privx_auth].api_`* credentials. The server uses it to look up the caller's PrivX user, roles, and permissions, which decide the tools that caller can see and call. It does not act as any user.
- **User connection** (per caller): opened for each tool call through the external token provider. The server signs a short-lived JWT for the caller's PrivX username and exchanges it for a PrivX token. Tools run on this connection, so PrivX authorizes and audits them as that user.

**Example configuration:**

```toml
[server]
# Use https:// for non-localhost deployments.
# Add tls_ params for setting up a certificate
public_url = "https://mcp.example.net:8181"

[privx_auth]
privx_base_url = "https://privx.example.net"

# User connection: values from the external token provider
rsa_key_file = "/secure/path/private-key.pem"
rsa_key_id = "privx-mcp-key-1"
audience = "privx-mcp-client"
token_issuer = "privx-mcp"

# API client connection: values from the PrivX API client
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "replace-me"
api_client_id = "replace-me"
api_client_secret = "replace-me"

[permissions]
# Users Directory type of the external token provider
source_type = "MICROSOFTGRAPH"
```

### User connection: external token provider

Register the server's public key as an [external token provider](../reference/server/privx-token-provider.md) in PrivX, and:

- point `[privx_auth].rsa_key_file` at the matching private key.
- from the provider, get values to set `[privx_auth].rsa_key_id`, `[privx_auth].audience`, `[privx_auth].token_issuer` (default `privx-mcp`), `[privx_auth].subject_format` (default `plain`), and `[permissions].source_type`.
- `[privx_auth].rsa_public_key_file` is an optional path to the public key, checked against the private key at startup.

### API client connection: PrivX API client

In PrivX, open **Administration → Deployment → Integrate with PrivX Using API Clients** and create an API client with a role that has `users-view` and `roles-view`. Copy its values into the four `[privx_auth].api_`* settings. If PrivX uses a private CA, set `[privx_auth].ca_cert` too.

See [PrivX configuration](../reference/server/privx.md) for how the two connections work, and the [reference documents](#reference) for more settings.

## 3) Set `auth_mode`

Set `[server].auth_mode` for your use case:

- `oauth` for regular user sign-in
- `m2m` for machine-to-machine service secrets
- `m2m-jwt` for a shared API key plus a bearer JWT

If you omit it, the default is `oauth`.

After finishing this page, use the bottom **Next** navigation and continue to either the OIDC (for oauth) or M2M page.

## 4) Decisions to make before continuing

### Transport security

Decide whether the server runs behind a reverse proxy.

- **Behind a TLS-terminating proxy, or in local development**: the server can listen on plain HTTP.
- **Without a proxy**: always use HTTPS. Set `[server].tls_cert_file` and `[server].tls_key_file`. The certificate can be self-signed or issued by a certificate authority.
- **In both cases**: `public_url` must use the scheme and address that clients actually reach.

See [TLS (HTTPS)](../reference/server/tls.md).

### User directory source

- Set `[permissions].source_type` to the PrivX directory that holds your users: `LOCAL`, `AD`, `MICROSOFTGRAPH`, etc.
- For an M2M setup, prefer a `LOCAL` user.

### Write safety

- Set `[permissions].default_read_only = true` until you have decided which write tools to allow.
- Later, use a whitelist and blacklist to control which tools are available.

## 5) Validate configuration before client onboarding

Start the server and check its logs for problems. Those logs are wherever your deployment writes them: process stdout, the system journal, Docker logs, or the equivalent.

If mandatory options are missing, the server will not start.

## Reference

- [MCP server configuration](../reference/server/SERVER.md)
- [External token provider](../reference/server/privx-token-provider.md)
- [PrivX configuration](../reference/server/privx.md)
- [TLS (HTTPS)](../reference/server/tls.md)
- [User-level security](../reference/security/user_level_security.md)

## Navigation

**Previous**: [Installation](02-install.md)

**Next**:

- [Configure OIDC](04-oidc.md) for browser clients
- [Configure machine-to-machine access](04-m2m/04-m2m.md) for clients that send their own bearer

---

**Overview**: [Documents Hub](../README.md)
