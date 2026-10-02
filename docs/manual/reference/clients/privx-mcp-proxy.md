# privx-mcp-proxy

Some MCP clients only connect through a local process. Others support HTTP but have OAuth limitations, such as fixed redirect URIs, incomplete dynamic client registration (DCR), or no support for confidential clients.

`privx-mcp-proxy` bridges those clients to the server. The client starts the proxy as a local process, and the proxy connects to `/mcp` over HTTP and handles the OIDC browser login. When the client's own HTTP OAuth works (`url` plus `auth`), use that instead of the proxy.

## Related documents

- [MCP client configuration](CLIENTS.md)
- [OIDC configuration](../oidc/OIDC.md)

IdP setup is the same as for native HTTP, so follow the provider guide above.

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

After login, the IdP redirects to a loopback URL, by default `http://localhost:<proxy-port>/oauth/callback`. Register that exact URI with the IdP, on the port the proxy uses. A mismatch produces `Invalid parameter: redirect_uri`.

## What the IdP client must look like

The proxy requires an IdP client with:

- the **confidential** client type
- a `client_id` and `client_secret`
- the authorization code flow with PKCE
- either `client_secret_post` or `client_secret_basic` authentication

Omitting `client_id` or `client_secret` does not fall back to a public client or to DCR. Those modes are not implemented.

The token audience must match `[oauth].audience` on the server. With Keycloak, add an audience mapper to the client as described in [Audience mapper](../oidc/keycloak.md#audience-mapper).

Web origins and CORS settings only matter if the browser hits CORS on the token endpoint from the callback origin, for example `http://localhost:3334`.

## Build the proxy

Without a distributed binary, build it from a clone of this repository, running the command from the repository root:

```bash
task build:proxy
```

This creates `bin/privx-mcp-proxy`. Use the absolute path to this binary when configuring your MCP client.

## Config file

Copy [privx-mcp-proxy.toml.example](../../../../privx-mcp-proxy.toml.example), then set `mcp_url` and the `[client]` fields. The file holds the OAuth application credentials (`client_id` and `client_secret`) and the connection settings, so keep it out of git.

The access and refresh tokens the IdP issues for the user after sign-in are stored separately, not in the TOML file:

- `$PRIVX_MCP_PROXY_AUTH_DIR`, when set
- `~/.mcp-auth/privx-mcp-proxy-v1`, by default

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

`allow_http` applies only to `mcp_url`, not to the OAuth callback. Leave it `false` when the MCP server uses HTTPS or runs locally on `localhost` or `127.0.0.1`. Set it to `true` only when the proxy must reach an MCP server over unencrypted HTTP on another host.

The `[callback]` fields configure the local OAuth redirect listener used during browser login. Together they form the redirect URI `http://{host}:{port}{path}`. Register that URI with the IdP and pin `port` to the registered value.

When `host` is `localhost`, the proxy still listens on `127.0.0.1`, but the IdP sees `localhost`. Register `127.0.0.1` only when you also set `host` to `127.0.0.1`.

## Client config

Point the client to the proxy binary and TOML file, using **absolute** paths, no `npx`, no `--transport` argument, and no `@` JSON files.

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

The proxy runs discovery, completes OAuth if needed (the first run may open a browser), sends `initialize` and `tools/list` to `/mcp`, and exits. It logs the HTTP headers with sensitive values redacted, and the session mode:

- `mode=stateless`: no `/mcp` response included `Mcp-Session-Id`.
- `mode=sessioned`: at least one `/mcp` response included `Mcp-Session-Id`.

### `--reset-session`

Forces a fresh login. Both the saved tokens and the IdP browser session are cached, so without the flag you stay signed in as the same user. This is useful when you need to switch user, for example to test a different role. The browser login sends `prompt=login`, so the IdP asks for credentials instead of reusing its session.

The saved token file is not read, written, or deleted. The new tokens live in memory until the client closes the proxy, and the next start without the flag goes back to the saved user. To sign in on every launch, keep the flag in the client args:

```json
"args": ["--reset-session", "/absolute/path/to/privx-mcp-proxy.toml"]
```

The flag can be combined with `--connect`.

## Logs

Logs go to **stderr** by default, or to `log_file` when that TOML field is set. While the client is connected, the proxy reserves stdout for MCP messages, except for `--help` and `--version`.

## Lifetime

The first connection may open a browser, later starts reuse the stored tokens, and the proxy refreshes the access token whenever a refresh token is available. It does not reopen the browser while it is already running.

If the IdP rejects a refresh token with `invalid_grant`, the proxy deletes the token file. Stop and start the proxy from the client to log in again.

If a remote `/mcp` session returns 404, the proxy reconnects and retries that `tools/call` once without restarting. It does not push a changed remote tool list to the client, so stop and start the proxy from the client to fetch a new `tools/list`.

## Native HTTP vs the proxy

Use native HTTP when it works, and the proxy when the client cannot use HTTP or its OIDC flow is unsuitable. A client with native HTTP OAuth connects directly to `/mcp` and uses its own callback URI rather than the proxy callback.

Both callbacks can be registered on one IdP client. See [Keycloak](../oidc/keycloak.md#keycloak-redirect-uris).

## Troubleshooting


| Symptom                           | What to check                                                                                                                                                                |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Invalid parameter: redirect_uri` | The IdP allow-list must match `http://localhost:<port>/oauth/callback` exactly: `localhost` against `127.0.0.1`, the pinned `callback.port`, and the path `/oauth/callback`. |
| Auth timeout                      | Raise `callback.auth_timeout_seconds`. The first connect needs a completed browser login.                                                                                    |
| Stale tokens                      | Delete this proxy's token store (see [Config file](#config-file)) and reconnect. Do not delete mcp-remote's store unless you used that Node tool.                            |
| Same user after deleting tokens   | The IdP browser session outlives the token file. Use `[--reset-session](#--reset-session)` to force a fresh login.                                                           |
| HTTP MCP URL refused              | Set `allow_http = true` for a non-loopback `http://` `mcp_url`.                                                                                                              |
