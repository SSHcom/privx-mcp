# PrivX configuration

The `[privx_auth]` section configures two separate connections from the MCP server to PrivX:

1. A non-user API client, used to resolve the logged-in user's PrivX account, roles, and permissions.
2. A user-specific client, used by MCP tools when they call PrivX APIs.

Keeping the connections separate lets the server decide which tools a user may access, while tool activity in PrivX stays attributed to that user.

## Related documents

- [MCP server configuration](SERVER.md)
- [OIDC configuration](../oidc/OIDC.md)
- [Configure machine-to-machine access](../../04-m2m.md)
- [User-level security](../security/user_level_security.md)

Parameter descriptions are in [MCP server configuration](SERVER.md#privx_auth).

## Non-user API client

The server creates this client at startup from the four `api_*` credentials:

- `api_oauth_client_id`
- `api_oauth_client_secret`
- `api_client_id`
- `api_client_secret`

The client is authenticated with API credentials, but anonymous with respect to the end user. PrivX can tell which configured client ID was used and see the originating host, but requests made through this connection are not attributed to a PrivX user.

The server uses it to find the PrivX user matching the verified OAuth identity and to resolve that user's roles and permissions, which determine the tools the user may see and call. Results are cached for `permissions.session_cache_ttl`, and a tool-call deny from that cache can trigger a throttled role refresh (`permissions.refresh_cooldown`). See [User-level security](../security/user_level_security.md#caching).

The API client is backed by a specific PrivX role and limited to that role's permissions. If user or permission resolution fails, check that the role holds the required permissions.

If PrivX uses a certificate signed by a private CA, `ca_cert` supplies an additional trust certificate, as either PEM content or a path to a PEM file. It applies to the non-user API client only.

## User-specific client

For each authenticated MCP user, the server creates a PrivX client through an external JWT token exchange:

1. The server verifies the bearer token issued by the configured OAuth provider. In `m2m` mode this check is a configured service secret instead of an IdP token, and the PrivX username is that secret's principal rather than a mapped claim.
2. In `oauth` mode, it reads the configured identity claim, such as `email`, and maps it to a PrivX username. `m2m` skips this step.
3. It creates a short-lived JWT whose `sub` claim identifies that username.
4. It signs the JWT with the RSA private key configured by `rsa_key_file`.
5. It exchanges the signed JWT with PrivX for a PrivX access token.
6. MCP tools use the resulting user-specific PrivX client.

The exchanged access token represents the identified PrivX user, so calls made by MCP tools are authorized and audited in PrivX as that user rather than as the non-user API client. Each authentication mints a fresh JWT and performs a new exchange. The JWT is valid for 90 seconds and is not reused as the tool credential.

The client is limited to the user's effective PrivX permissions, derived from all roles assigned to the user.

Restricted MCP tools are assigned the PrivX permissions they require, such as `hosts-view` or `users-manage`. The server resolves the user's roles and filters the tool catalog accordingly, including each role's configured validity days and time windows, which avoids sending requests that PrivX would reject while a role restriction is in effect. Calls made through an available tool remain subject to PrivX's own authorization checks.

## Configuring trust between the MCP server and PrivX

PrivX must be configured to trust JWTs issued by the MCP server. Generate an RSA key pair, keep the private key on the MCP server, and register the public key with the PrivX External Token Provider.

### 1. Generate an RSA key pair

```bash
openssl genrsa -out signing-key.pem 2048
openssl rsa -in signing-key.pem -pubout -out signing-key-pub.pem
```

Keep `signing-key.pem` on the MCP server, point `rsa_key_file` at it, and do not commit it. Upload `signing-key-pub.pem` to PrivX in the next step.

### 2. Register the public key in PrivX

In the PrivX Admin UI, open **Administration -> Deployment -> External Token Authentication** and add a new token provider:

- **Issuer name**: must match `token_issuer` in the MCP server config.
- **Token Provider Public Key**: upload `signing-key-pub.pem`.
- **Key ID**: must match `rsa_key_id` in the MCP server config.
- **Subject Type**: `Plain` or `DN`, matching `subject_format` (`plain` to Plain, `dn` to DN).
- **Users Directory**: the directory holding your MCP users. It must line up with `permissions.source_type`, see [Identity alignment with PrivX](SERVER.md#identity-alignment-with-privx).

### 3. Matching config values

These values must agree with the External Token Provider configuration in PrivX:

| Parameter        | JWT field    | Purpose                                                                           |
| ---------------- | ------------ | --------------------------------------------------------------------------------- |
| `rsa_key_id`     | `kid` header | Selects the public key PrivX uses to verify the signature.                        |
| `token_issuer`   | `iss` claim  | Identifies the MCP server as the token issuer. Defaults to `privx-mcp`.           |
| `audience`       | `aud` claim  | Identifies PrivX as the intended audience.                                        |
| `subject_format` | `sub` claim  | Uses either the mapped username (`plain`, the default) or `CN=<username>` (`dn`). |

`rsa_public_key_file` is optional. When configured, the server verifies at startup that it matches the private key in `rsa_key_file`. This catches a mismatched local key pair, but does not verify that the same public key is registered in PrivX.

`oauth.identity_claim_field` selects the OAuth claim that identifies the user, such as `email`. `oauth.identity_mapping_rule` controls how that value becomes a PrivX username: `as-is` keeps it unchanged, `strip-domain` removes the domain from an email-like value. The resulting username must identify a user that PrivX accepts through the External Token Provider.

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
