# Configure the server

Create a `privx-mcp-config.toml` file that configures the server.

## 1) Start from the example file

Create `privx-mcp-config.toml`. In the GitHub repository, find `privx-mcp-config-example.toml` at the repository root, then copy its contents and paste them into the new file. The example file carries the full schema.

## 2) Fill the minimum required settings

Example:

```toml
[server]
# Use https:// for non-localhost deployments.
# Add tls_ params for setting up a certificate
public_url = "https://mcp.example.net:8181"


[privx_auth]
privx_base_url = "https://privx.example.net"
rsa_key_file = "/secure/path/private-key.pem"
rsa_key_id = "privx-mcp-key-1"
audience = "privx-mcp-client"
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "replace-me"
api_client_id = "replace-me"
api_client_secret = "replace-me"

[permissions]
# Set this to the PrivX user directory source you use.
source_type = "MICROSOFTGRAPH"
```

This step covers the required settings that every setup needs.

See the [reference documents](#reference) for more settings.

## 3) Set `auth_mode`

Set `[server].auth_mode` for your use case:

- `oauth` for regular user sign-in
- `m2m` for machine-to-machine service secrets

If you omit it, the default is `oauth`.

After finishing this page, use the bottom **Next** navigation and continue to either the OIDC (for oauth) or M2M page.

## 4) Decisions to make before continuing

### Transport security

Decide whether the server runs behind a reverse proxy.

- **Behind a TLS-terminating proxy, or in local development**: the server can listen on plain HTTP.
- **Without a proxy**: always use HTTPS. Set `[server].tls_cert_file` and `[server].tls_key_file`. The certificate can be self-signed or issued by a certificate authority.
- **In both cases**: `public_url` must use the scheme and address that clients actually reach.

See [TLS (HTTPS)](reference/server/tls.md).

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

- [MCP server configuration](reference/server/SERVER.md)
- [PrivX configuration](reference/server/privx.md)
- [TLS (HTTPS)](reference/server/tls.md)
- [User-level security](reference/security/user_level_security.md)

## Navigation

**Previous**: [Installation](02-install.md)

**Next**:
- [Configure OIDC](04-oidc.md) for browser clients
- [Configure machine-to-machine access](04-m2m.md) for clients that send their own bearer

---

**Overview**: [Manual](README.md) | [Documents Hub](../README.md)
