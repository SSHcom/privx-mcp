# MCP server configuration

Every section and parameter in `privx-mcp-config-example.toml`. It is assumed you have copied that file to your own `privx-mcp-config.toml`.

The server can also be configured entirely through the environment. See [.env-example](../../../../.env-example) for the variable names. Values are loaded in this order:

1. Config file, skipped when missing.
2. Defaults for unset optional keys.
3. Environment overrides.
4. Validation.

## Contents

- [`[server]`](#server)
- [`[privx_auth]`](#privx_auth)
- [`[permissions]`](#permissions)
- [`[oauth]`](#oauth)
- [Identity alignment with PrivX](#identity-alignment-with-privx)
- [Troubleshooting](#troubleshooting)

## Related documents

- [PrivX configuration](privx.md)
- [TLS (HTTPS)](tls.md)
- [OIDC configuration](../oidc/OIDC.md)
- [Configure machine-to-machine access](../../04-m2m.md)
- [User-level security](../security/user_level_security.md)
- [Security considerations](../security/security.md)

## `[server]`

| Parameter                      | Description                                                                                                                                                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                         | **(optional)** MCP server name exposed to clients. Defaults to `privx-mcp-server`.                                                                                                                                 |
| `version`                      | **(optional)** MCP server version string. Defaults to `unknown`.                                                                                                                                                   |
| `public_url`                   | Public base URL for this server (for example `http://localhost:8181`). Required. Use `https://` when server TLS is enabled. `http` is allowed in both `oauth` and `m2m` (for example TLS terminated at a reverse proxy); startup logs a warning when `public_url` is not `https`. |
| `auth_mode`                    | **(optional)** `oauth` (default) or `m2m`. One process uses one mode. `oauth` requires `oauth.issuer_url` and `oauth.audience`, and `service_secrets` must be empty. `m2m` requires `service_secrets` and rejects `oauth.issuer_url`, `oauth.audience`, `oauth.jwks_uri`, `oauth.scopes`, and the DCR stub settings. |
| `service_secrets`              | **(optional)** In `m2m`, required. A list of `username secret` pairs separated by `\|`. The first space separates the username from the secret. Each secret must be at least 32 characters. The same username may appear twice. The same secret may not. Usernames and secrets cannot contain a space or `\|`. Empty in `oauth` mode. `SERVER_SERVICE_SECRETS` replaces the whole value. |
| `listen_addr`                  | **(optional)** HTTP bind address (for example `:8181`). When omitted, derived from the `server.public_url` port, fallback `:8181`.                                                                                 |
| `disable_localhost_protection` | **(optional)** Maps to the MCP Go SDK `DisableLocalhostProtection` option. Default `false`. Keep `false` for localhost/loopback deployments unless you intentionally need to disable localhost Host-header checks. |
| `stateless`                    | **(optional)** Maps to Streamable HTTP `Stateless` mode. Default `true`. When `true`, `/mcp` runs without `Mcp-Session-Id`. When `false`, clients use sessioned requests with `Mcp-Session-Id`.                    |
| `tls_cert_file`                | **(optional)** Path to a TLS certificate PEM file. Enables TLS, and must be set together with `tls_key_file`. See [TLS (HTTPS)](tls.md) for how to create a self-signed certificate.                               |
| `tls_key_file`                 | **(optional)** Path to a TLS private-key PEM file. Must be set together with `tls_cert_file`.                                                                                                                      |
| `log_file`                     | **(optional)** Active log file path. Empty (default) writes to stdout. When set, the logger appends to this path and keeps up to 5 rotated backups (100MB each) in the same directory.                             |
| `log_level`                    | **(optional)** Minimum slog level: `error`, `warn`, `info`, or `debug`. Defaults to `info`.                                                                                                                        |

Environment equivalents for the two SDK options are `SERVER_DISABLE_LOCALHOST_PROTECTION` and `SERVER_STATELESS`.

With `log_level = "debug"`, each `/mcp` request log includes `mcp_session_id_present` and `using_mode`, so you can verify at runtime whether traffic is sessioned or stateless.

## `[privx_auth]`

The `rsa_*`, `audience`, `token_issuer`, and `subject_format` values configure the JWT exchange that gives each caller a user-specific PrivX connection. The `api_*` values and `ca_cert` configure the non-user API client used for server-level lookups. See [PrivX configuration](privx.md) for how the two connections differ.

| Parameter                 | Description                                                                                                                       |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `privx_base_url`          | Base URL of your PrivX deployment, for example `https://privx.example.com`.                                                       |
| `rsa_key_file`            | Path to the RSA private key (PEM) used to sign tokens minted for PrivX.                                                           |
| `rsa_public_key_file`     | **(optional)** Path to the corresponding RSA public key. When set, the server verifies that it matches `rsa_key_file` at startup. |
| `rsa_key_id`              | JWT `kid` value. Must match the Key ID configured in the PrivX External Token Provider.                                           |
| `audience`                | JWT `aud` claim for tokens minted to PrivX. Should match the PrivX External Token Provider audience.                              |
| `token_issuer`            | **(optional)** JWT `iss` claim for tokens minted to PrivX. Defaults to `privx-mcp`.                                               |
| `subject_format`          | **(optional)** Subject format for minted JWTs, either `plain` or `dn`. Defaults to `plain`.                                       |
| `api_oauth_client_id`     | OAuth client ID of the PrivX API client.                                                                                          |
| `api_oauth_client_secret` | OAuth client secret of the PrivX API client.                                                                                      |
| `api_client_id`           | PrivX API client ID.                                                                                                              |
| `api_client_secret`       | PrivX API client secret.                                                                                                          |
| `ca_cert`                 | **(optional)** Custom CA trust certificate for the PrivX TLS connection, as PEM content or a path to a PEM file.                  |

## `[permissions]`

| Parameter                   | Description                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `default_read_only`         | **(optional)** Global read-only gate for tool access. Defaults to `true`.                                                                                                                                                                                                                                                                                             |
| `whitelist`                 | **(optional)** Prefix allow-list for tool names (for example `["host-", "user-"]`). Empty means no allow-list filtering.                                                                                                                                                                                                                                              |
| `blacklist`                 | **(optional)** Prefix deny-list for tool names, applied after `whitelist`. Empty means no deny-list filtering.                                                                                                                                                                                                                                                        |
| `session_cache_ttl`         | **(optional)** Cache TTL for resolved user/permission context. Defaults to `30s`. Use `0` to disable caching. Must be non-negative.                                                                                                                                                                                                                                   |
| `refresh_cooldown`          | **(optional)** Minimum interval between on-deny PrivX role refreshes for the same identity. Defaults to `1m`. Use `0` to disable on-deny refresh. Must be non-negative. After a completed refresh the call result includes a `roles_changed` / `restart_host_application` payload, because the official SDK cannot notify a single session with `tools/list_changed`. |
| `source_type`               | PrivX user-directory source used to resolve identities (for example `AD`, `LOCAL`, or `MICROSOFTGRAPH`). Required.                                                                                                                                                                                                                                                    |
| `request_window_seconds`    | **(optional)** Fixed rate-limit window per identity, in seconds. Must be non-negative, and set above zero together with `max_requests_per_window`.                                                                                                                                                                                                                    |
| `max_requests_per_window`   | **(optional)** Maximum tool calls per identity in each fixed window. Must be non-negative, and set above zero together with `request_window_seconds`.                                                                                                                                                                                                                 |
| `maxed_window_wait_seconds` | **(optional)** Extra cooldown, in seconds, after a window that used the full quota. The next window cannot start until the request window ends and this wait has elapsed. Must be non-negative. Zero (default) disables the extra wait, and any value above zero requires the other two rate-limit settings to be above zero.                                         |

Rate-limit sizing guidance: [Security considerations](../security/security.md#loop-and-ddos-protection).

## `[oauth]`

| Parameter                | Description                                                                                                                                                                                                                                                                                                      |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer_url`             | OIDC issuer/discovery URL used to verify incoming bearer tokens. Required when `server.auth_mode` is `oauth`. Must be empty in `m2m`.                                                                                                                                                                            |
| `scopes`                 | **(optional)** Client compatibility hint for scope selection. Not used for token verification, and clients may still choose their own scopes.                                                                                                                                                                    |
| `audience`               | Expected token audience (`aud`) for `/mcp` requests. Required when `server.auth_mode` is `oauth`. Must be empty in `m2m`.                                                                                                                                                                                        |
| `jwks_uri`               | **(optional)** JWKS endpoint override, skipping discovery-based JWKS URL resolution.                                                                                                                                                                                                                             |
| `jwks_cache_ttl`         | **(optional)** JWKS cache duration. Defaults to `1h`.                                                                                                                                                                                                                                                            |
| `identity_claim_field`   | **(optional)** Claim path used to resolve the PrivX identity from an OAuth token (for example `preferred_username` or `email`). Defaults to `email`. Used only in `oauth` mode; not required and not used in `m2m`.                                                                                         |
| `identity_mapping_rule`  | **(optional)** Identity mapping before PrivX lookup, either `as-is` or `strip-domain`. Defaults to `as-is`. Used only in `oauth` mode; not required and not used in `m2m`.                                                                                                                                        |
| `dcr_stub_client_id`     | **(optional)** Static client ID returned by the DCR stub. Setting it enables the `/register` endpoint, for MCP clients that require [Dynamic Client Registration](../oidc/OIDC.md#dynamic-client-registration-dcr) when the IdP does not support it, such as [Microsoft Entra ID](../oidc/entra-id/ENTRA-ID.md). |
| `dcr_stub_client_secret` | **(optional)** Static client secret returned by the DCR stub.                                                                                                                                                                                                                                                    |

## Identity alignment with PrivX

Tool calls reach PrivX as the caller's own PrivX user. In `oauth` mode the server mints a JWT for the identity behind the incoming access token. In `m2m` mode the JWT subject is the username bound to the matched secret, and identity claim mapping is not applied. Either way it exchanges that JWT with a PrivX **External Token Provider**, configured under `Administration -> Deployment -> External Token Authentication`. [PrivX configuration](privx.md) covers the exchange and the signing-key registration that makes PrivX trust the minted token. `permissions.source_type` and the provider's users directory still have to agree in both modes.

For PrivX to resolve the identity inside that token, three settings must agree:

- MCP `[oauth]` identity mapping (`identity_claim_field`, `identity_mapping_rule`)
- MCP `[permissions].source_type`
- The **Users Directory** field of the PrivX External Token Provider

### Local users setup

Use this when the target PrivX users are in a Local User Directory:

- `[oauth].identity_claim_field` / `OAUTH_ID_CLAIM_FIELD` = `preferred_username`
- `[oauth].identity_mapping_rule` / `OAUTH_ID_MAPPING_RULE` = `as-is`
- `[permissions].source_type` / `PERMISSIONS_SOURCE_TYPE` = `LOCAL`
- **Users Directory** = a directory of type **Local User Directory**, often named `Local users`

### Entra ID setup

Use this when the target PrivX users are in a Microsoft Graph directory:

- `[oauth].identity_claim_field` / `OAUTH_ID_CLAIM_FIELD` = `email`
- `[oauth].identity_mapping_rule` / `OAUTH_ID_MAPPING_RULE` = `as-is`
- `[permissions].source_type` / `PERMISSIONS_SOURCE_TYPE` = `MICROSOFTGRAPH`
- **Users Directory** = a directory of type **Microsoft Graph**

## Troubleshooting

| Symptom                           | What to check                                                                                                                                                                                      |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client refuses HTTP               | Configure HTTPS by setting `tls_cert_file` and `tls_key_file`. See [TLS (HTTPS)](tls.md).                                                                                                          |
| User sees no tools, or too few    | Check `permissions.default_read_only`, the `whitelist` / `blacklist` prefixes, and `permissions.source_type`. See [User-level security](../security/user_level_security.md#quick-troubleshooting). |
| `Invalid parameter: redirect_uri` | The IdP must allow-list the URI the client sends. Take the value from [MCP client configuration](../clients/CLIENTS.md#redirect-uris).                                                             |
| Auth timeout                      | Complete the browser login on first connect. For the proxy, see [privx-mcp-proxy](../clients/privx-mcp-proxy.md#troubleshooting).                                                                  |
