# privx-mcp-proxy

`privx-mcp-proxy` bridges MCP clients to the server when they cannot connect over HTTP themselves. Use it when a client:

- only connects through a local process, or
- supports HTTP but has OAuth limitations, such as fixed redirect URIs, incomplete dynamic client registration (DCR), or no support for confidential clients.

The client starts the proxy as a local process. The proxy connects to `/mcp` over HTTP and handles the OIDC browser login.

If the client's own HTTP OAuth works (`url` plus `auth`), connect it directly to `/mcp` instead and skip the proxy. A directly connected client uses its own callback URI rather than the proxy callback. Both callbacks can be registered on the same IdP client, see [Keycloak](../oidc/keycloak.md#keycloak-redirect-uris).

## Related documents

- [MCP client configuration](CLIENTS.md)
- [OIDC configuration](../oidc/OIDC.md)

IdP setup is the same as for a direct connection, so follow the provider guide above.

## How it fits

```
MCP client
         →  privx-mcp-proxy
              HTTP  →  POST {mcp_url}
              401   →  RFC 9728 discovery (/.well-known/oauth-protected-resource)
              browser → your OIDC issuer
              redirect → http://localhost:<proxy-port>/oauth/callback
              Bearer  → further /mcp calls
```

After login, the IdP redirects to a loopback URL, by default `http://localhost:<proxy-port>/oauth/callback`. Register that exact URI, including the port, with the IdP. A mismatch produces `Invalid parameter: redirect_uri`.

## What the IdP client must look like

The proxy requires an IdP client with:

- the **confidential** client type
- a `client_id` and `client_secret`
- the authorization code flow with PKCE
- either `client_secret_post` or `client_secret_basic` authentication
- a token audience matching `[oauth].audience` on the server (with Keycloak, add an [audience mapper](../oidc/keycloak.md#audience-mapper))

Public clients and DCR are not implemented, so `client_id` and `client_secret` are both required.

Web origins and CORS settings only matter if the browser hits CORS on the token endpoint from the callback origin, for example `http://localhost:3334`.

## Build the proxy

Without a distributed binary, build it from the repository root:

```bash
task build:proxy
```

This creates `bin/privx-mcp-proxy`. Use its absolute path when configuring your MCP client.

## Config file

Copy [privx-mcp-proxy-example.toml](../../../privx-mcp-proxy-example.toml), then set `mcp_url` and the `[client]` fields. The file holds the OAuth client credentials, so keep it out of git.

```toml
mcp_url = "http://localhost:8181/mcp"
allow_http = false
log_level = "info"

[callback]
host = "localhost"
port = 3334
path = "/oauth/callback"
auth_timeout_seconds = 60

# These settings must match the OAuth client configured in the IdP.
[client]
client_id = "privx-mcp-client"
client_secret = "<client-secret>"
scopes = ["openid", "profile", "email", "offline_access"]
token_endpoint_auth_method = "client_secret_post"
```

The user's access and refresh tokens are not stored in the TOML file but in:

- `$PRIVX_MCP_PROXY_AUTH_DIR`, when set
- `~/.mcp-auth/privx-mcp-proxy-v1`, by default

### `allow_http`

Applies to every outbound request (MCP URL, OAuth metadata, and token requests), not to the local callback listener.

- `false` (default): HTTPS everywhere, plain HTTP only on `localhost` or `127.0.0.1`.
- `true`: also allows unencrypted HTTP to other hosts. Use only when required.

### `[callback]`

Configures the local redirect listener for browser login. The redirect URI is `http://{host}:{port}{path}`.

- Register that URI with the IdP and pin `port` to the registered value.
- With `host = "localhost"`, the proxy listens on `127.0.0.1` but the IdP sees `localhost`. Register `127.0.0.1` only when `host` is also `127.0.0.1`.

## Client config

Point the client to the proxy binary and TOML file:

- use **absolute** paths
- no `npx`, no `--transport` argument, and no `@` JSON files

```json
{
  "mcpServers": {
    "privx-mcp": {
      "command": "/absolute/path/to/privx-mcp-proxy",
      "args": ["/absolute/path/to/privx-mcp-proxy.toml"]
    }
  }
}
```

Key names and file format differ by client. See [MCP client configuration](CLIENTS.md) for per-client details.

## Command-line arguments

```
privx-mcp-proxy [--connect] [--reset-session] <config>.toml
privx-mcp-proxy --help | --version
```

| Argument          | Purpose                                                                      |
| ----------------- | ---------------------------------------------------------------------------- |
| `<config>.toml`   | Path to the proxy config file. Required unless `--help`/`--version` is used. |
| `--connect`       | Smoke test: connect, list tools, and exit.                                   |
| `--reset-session` | Force a fresh login, for example to switch user.                             |
| `--help`          | Show help.                                                                   |
| `--version`       | Print version.                                                               |

### `--connect`

Tests the setup without a client:

```bash
./bin/privx-mcp-proxy --connect /absolute/path/to/privx-mcp-proxy.toml
```

The proxy:

1. runs discovery and completes OAuth if needed (the first run may open a browser)
2. sends `initialize` and `tools/list` to `/mcp`
3. logs the HTTP headers, with sensitive values redacted, and the session mode
4. exits

The session mode is one of:

- `mode=stateless`: no `/mcp` response included `Mcp-Session-Id`.
- `mode=sessioned`: at least one `/mcp` response included `Mcp-Session-Id`.

### `--reset-session`

Forces a fresh login, for example to test a different role. Without it, the saved tokens and the IdP browser session keep you signed in as the same user.

- The browser login sends `prompt=login`, so the IdP asks for credentials instead of reusing its session.
- The saved token file is not read, written, or deleted. New tokens live in memory until the client closes the proxy.
- The next start without the flag goes back to the saved user.
- It can be combined with `--connect`.

To sign in on every launch, keep the flag in the client args:

```json
"args": ["--reset-session", "/absolute/path/to/privx-mcp-proxy.toml"]
```

## Logs

Logs go to **stderr** by default, or to `log_file` when that TOML field is set. While the client is connected, stdout is reserved for MCP messages (except for `--help` and `--version`).

## Lifetime

- The first connection may open a browser. Later starts reuse the stored tokens.
- The access token is refreshed whenever a refresh token is available. A running proxy does not reopen the browser.
- If the IdP rejects a refresh token with `invalid_grant`, the proxy deletes the token file. Restart the proxy from the client to log in again.
- If a remote `/mcp` session returns 404, the proxy reconnects and retries that `tools/call` once.
- A changed remote tool list is not pushed to the client. Restart the proxy from the client to fetch a new `tools/list`.

## Security concerns

The proxy sends the access token and MCP request bodies only to absolute `http` or `https` URLs. Other schemes, including `file`, are refused for `mcp_url`, OAuth metadata, token requests, discovered authorization and token endpoints, and redirects.

Plain HTTP:

- With `allow_http = false`, plain HTTP is limited to `localhost` and `127.0.0.1`. Every other host, including one named by a redirect, must use HTTPS.
- With `allow_http = true`, the access token and tool-call arguments are visible to the network between the proxy and a non-loopback HTTP host.
- The local OAuth callback listener always uses loopback HTTP and is not affected.

Redirects (MCP calls, metadata fetches, and token requests):

- Followed only when the hostname matches the first request. Default ports `443` and `80` count as the same host, so a path change such as a trailing slash from a load balancer is followed.
- Refused when the host or port changes, which keeps the access token and request body on the original host. A load balancer in front of the MCP server therefore keeps the client on the load balancer's address.

## Troubleshooting

| Symptom                           | What to check                                                                                                                                                                |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Invalid parameter: redirect_uri` | The IdP allow-list must match `http://localhost:<port>/oauth/callback` exactly: `localhost` against `127.0.0.1`, the pinned `callback.port`, and the path `/oauth/callback`. |
| Auth timeout                      | Raise `callback.auth_timeout_seconds`. The first connect needs a completed browser login.                                                                                    |
| Stale tokens                      | Delete this proxy's token store (see [Config file](#config-file)) and reconnect. Do not delete mcp-remote's store unless you used that Node tool.                            |
| Same user after deleting tokens   | The IdP browser session outlives the token file. Use [`--reset-session`](#--reset-session) to force a fresh login.                                                           |
| HTTP MCP URL refused              | Set `allow_http = true` for a non-loopback `http://` `mcp_url`.                                                                                                              |
