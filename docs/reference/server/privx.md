# PrivX configuration

The `[privx_auth]` section configures two separate connections from the MCP server to PrivX:

1. A non-user API client, used to resolve the logged-in user's PrivX account, roles, and permissions.
2. A user-specific client, used by MCP tools when they call PrivX APIs.

Keeping the connections separate lets the server decide which tools a user may access, while tool activity in PrivX stays attributed to that user.

## Related documents

- [MCP server configuration](SERVER.md)
- [External token provider](privx-token-provider.md)
- [OIDC configuration](../oidc/OIDC.md)
- [Configure machine-to-machine access](../../guide/04-m2m/04-m2m.md)
- [User-level security](../security/user_level_security.md)

Parameter descriptions are in [MCP server configuration](SERVER.md#privx_auth).

## Non-user API client

The server creates this client at startup from the four `[privx_auth].api_*` credentials:

- `[privx_auth].api_oauth_client_id`
- `[privx_auth].api_oauth_client_secret`
- `[privx_auth].api_client_id`
- `[privx_auth].api_client_secret`

The client is authenticated with API credentials, but anonymous with respect to the end user. PrivX can tell which configured client ID was used and see the originating host, but requests made through this connection are not attributed to a PrivX user.

The server uses it to find the PrivX user matching the verified OAuth identity and to resolve that user's roles and permissions, which determine the tools the user may see and call. A match and a lookup that finds no user are both cached for `[permissions].session_cache_ttl`. A tool-call deny from a cached match can trigger a throttled role refresh (`[permissions].refresh_cooldown`). See [User-level security](../security/user_level_security.md#caching).

The API client is backed by a specific PrivX role and limited to that role's permissions. The role needs `users-view` and `roles-view`. If user or permission resolution fails, check that the role holds them.

If PrivX uses a certificate signed by a private CA, `[privx_auth].ca_cert` supplies an additional trust certificate, as either PEM content or a path to a PEM file. It applies to the non-user API client only.

## User-specific client

For each authenticated MCP user, the server creates a PrivX client through an external JWT token exchange:

1. The server verifies the bearer token issued by the configured OAuth provider. In `m2m` mode this check is a configured service secret instead of an IdP token, and the PrivX username is that secret's principal rather than a mapped claim. In `m2m-jwt` mode the client presents `X-API-KEY` and a bearer JWT, and the PrivX username comes from `[server].m2m_jwt_identity_mapper`.
2. In `oauth` mode, it reads the configured identity claim, such as `email`, and maps it to a PrivX username. `m2m` and `m2m-jwt` skip this step.
3. It creates a short-lived JWT whose `sub` claim identifies that username.
4. It signs the JWT with the RSA private key configured by `[privx_auth].rsa_key_file`.
5. It exchanges the signed JWT with PrivX for a PrivX access token.
6. MCP tools use the resulting user-specific PrivX client.

The exchanged access token represents the identified PrivX user, so calls made by MCP tools are authorized and audited in PrivX as that user rather than as the non-user API client. Each tool call mints a fresh JWT and performs a new exchange. The JWT is valid for 90 seconds and is not reused as the tool credential.

The client is limited to the user's effective PrivX permissions, derived from all roles assigned to the user.

Restricted MCP tools are assigned the PrivX permissions they require, such as `hosts-view` or `users-manage`. The server resolves the user's roles and filters the tool catalog accordingly, including each role's configured validity days and time windows, which avoids sending requests that PrivX would reject while a role restriction is in effect. Calls made through an available tool remain subject to PrivX's own authorization checks.

## Configuring trust between the MCP server and PrivX

PrivX must be configured to trust JWTs issued by the MCP server. Generate an RSA key pair, keep the private key on the MCP server, and register the public key with the [external token provider](privx-token-provider.md).

### 1. Generate an RSA key pair

```bash
openssl genrsa -out signing-key.pem 2048
openssl rsa -in signing-key.pem -pubout -out signing-key-pub.pem
```

Keep `signing-key.pem` on the MCP server, point `[privx_auth].rsa_key_file` at it, and do not commit it. Register `signing-key-pub.pem` in PrivX in the next step.

### 2. Register the public key in PrivX

Register the public key as an [external token provider](privx-token-provider.md) in PrivX, and:

- point `[privx_auth].rsa_key_file` at the matching private key.
- from the provider, get values to set `[privx_auth].rsa_key_id` (Key ID), `[privx_auth].audience` (Service Name in Audience Claim), `[privx_auth].token_issuer` (Issuer, default `privx-mcp`), `[privx_auth].subject_format` (Subject Type, default `plain`), and `[permissions].source_type` (type of the Users Directory).
- `[privx_auth].rsa_public_key_file` is an optional path to the public key, checked against the private key at startup.

`[oauth].identity_claim_field` selects the OAuth claim that identifies the user, such as `email`. `[oauth].identity_mapping_rule` controls how that value becomes a PrivX username: `as-is` keeps it unchanged, `strip-domain` removes the domain from an email-like value. The resulting username must identify a user in the directory selected on the external token provider.

## Example

```toml
[privx_auth]
privx_base_url = "https://privx.example.com"

# External JWT exchange for user-specific tool calls
rsa_key_file = "/etc/privx-mcp/private-key.pem"
# rsa_public_key_file = "/etc/privx-mcp/public-key.pem"
rsa_key_id = "privx-mcp-key-1"
token_issuer = "privx-mcp"
audience = "privx-mcp-client"
subject_format = "plain"

# Non-user client for PrivX user and permission resolution
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "replace-with-secret"
api_client_id = "replace-with-api-client-id"
api_client_secret = "replace-with-api-client-secret"

# Optional private CA used by the non-user API client
# ca_cert = "/etc/privx-mcp/privx-ca.pem"

[oauth]
identity_claim_field = "email"
identity_mapping_rule = "as-is"
```

Store the RSA private key and all client secrets securely, restrict access to the MCP server process, and do not commit them to source control.
