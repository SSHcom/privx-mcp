# MCP client configuration

How each client connects, using `mcp.json` or equivalent, and which callbacks each one offers as redirect URLs for OIDC providers.

This server is **streamable HTTP** at `/mcp` (no SSE). Prefer native HTTP when the client supports MCP OAuth. Use [privx-mcp-proxy](privx-mcp-proxy.md) locally as an alternative stdio bridge.

## Related documents

- [privx-mcp-proxy](privx-mcp-proxy.md)
- [OIDC configuration](../oidc/OIDC.md)
- [TLS (HTTPS)](../server/tls.md)

MCP clients change quickly, so config paths, callback URLs, and OAuth support can be out of date here. Check the client's own manual when something does not work, and see [known issues](#known-issues) at the end of this page.

## HTTP or HTTPS

Clients do not agree on whether a plain-HTTP MCP server is acceptable, so the strictest client you use effectively decides the server's `public_url` scheme. HTTP is never recommended in production.

The table below shows clients with known HTTP restrictions.

| Client          | Description                                                               |
| --------------- | ------------------------------------------------------------------------- |
| Claude Desktop  | Only supports secure MCP servers over HTTPS                               |
| Kiro            | Rejected unless the host is `localhost`. Use HTTPS for any other hostname |
| privx-mcp-proxy | Accepted only with `allow_http = true` in the TOML (non-loopback `http`)  |

Enabling TLS on the server: [TLS (HTTPS)](../server/tls.md).

## Clients with limited OAuth capabilities

Some clients do not support or are difficult to set up with OAuth authentication.

The table below shows clients having such issues.

| Client       | Description                                                                                                                                                                                                                                                    |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kiro         | A static client is difficult to set up, so use Dynamic Client Registration (DCR) with native HTTP. Add a [DCR stub](../oidc/OIDC.md#dynamic-client-registration-dcr) when the IdP has no DCR of its own, or use [privx-mcp-proxy](privx-mcp-proxy.md) instead. |
| OpenAI Codex | OAuth works but is complicated to configure. Use DCR with native HTTP, or [privx-mcp-proxy](privx-mcp-proxy.md).                                                                                                                                               |

## Redirect URIs

| Client            | Redirect URL                                                                        | Note                                                                         |
| ----------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Claude Code       | `https://<host>:<port>/callback`                                                    | Set `callbackPort` in config and use the matching callback URL               |
| Claude Desktop    | `https://claude.ai/api/mcp/auth_callback` and `https://claude.ai/api/auth/callback` | Add both as redirect URLs                                                    |
| Copilot (VS Code) | `https://vscode.dev/redirect` and `http://localhost:33418/`                         | Add both as redirect URLs                                                    |
| Cursor            | `http://localhost:8787/callback`                                                    | Older Cursor versions may use `cursor://anysphere.cursor-mcp/oauth/callback` |
| Kiro              | Not applicable for DCR                                                              | No pre-registered redirect is needed for DCR                                 |
| MCP Inspector     | `http://localhost:6274/oauth/callback`                                              |                                                                              |
| privx-mcp-proxy   | `http://localhost:<port>/oauth/callback`                                            | Port is `callback.port` in the TOML (default 3334)                           |
| OpenAI Codex      | Not applicable for DCR                                                              | Use DCR (native HTTP) or [privx-mcp-proxy](privx-mcp-proxy.md)               |

**Note**: `localhost` and `127.0.0.1` are different URLs to every provider. If one does not work, try the other.

## Claude Code

Config file: `<project>/.mcp.json` or `~/.claude.json`

Example using a static OAuth client:

```json
{
  "mcpServers": {
    "privx-mcp": {
      "type": "http",
      "url": "https://example-mcp.demo.net:8181/mcp",
      "oauth": {
        "clientId": "privx-mcp-client",
        "callbackPort": 3334
      }
    }
  }
}
```

Notes:

- You will be asked for the client secret when connecting.
- Redirect URL is `https://<host>:<port>/callback`, where `<port>` matches `oauth.callbackPort`.

## Claude Desktop

Only secure MCP servers (HTTPS) are supported.

Open user menu -> **Settings** -> **Connectors** -> **Add**.

In the **Name and URL** dialog:

- Fill in name and URL as `https://<host>:<port>/mcp`
- Click **Continue**

In the **Add custom connector** dialog:

- Choose **Sign in now**
- Choose **Use your own OAuth client** and fill in client ID and client secret from the IdP
- Click **Add**

Redirect URIs to add in the IdP client:

- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.ai/api/auth/callback`

## Copilot (VS Code)

Config file: `<project>/.vscode/mcp.json` or `~/.config/[Code | Code - OSS]/User/mcp.json`

The global path depends on the VS Code distribution.

Example using a static OAuth client:

```json
{
  "servers": {
    "privx-mcp": {
      "type": "http",
      "url": "https://example-mcp.demo.net:8181/mcp"
    }
  }
}
```

Notes:

- The client ID and secret are not stored in the config file, but VS Code opens a pop-up where you can provide them.
- Copilot supports DCR and may first attempt to authenticate using that.

Safest way to add a server entry:

1. Open **Settings** -> **MCP Servers**.
2. Click `[+]` to add a new server.
3. Select `HTTP` as type.
4. Enter the URL (`https://<host>:<port>/mcp`) and any server name, for example `privx-mcp`.
5. Choose workspace (project) or global scope, then save.

VS Code opens the config file and adds controls above the server name. Use them to start and stop the server and to reach the server actions.

Redirect URIs to add in the IdP client:

- `https://vscode.dev/redirect`
- `http://localhost:33418/`, keeping the trailing slash. If that fails, also add `http://127.0.0.1:33418`.

## Cursor

Config file: `<project>/.cursor/mcp.json` or `~/.cursor/mcp.json`

Example using a static OAuth client:

```json
{
  "mcpServers": {
    "privx-mcp": {
      "url": "https://example-mcp.demo.net:8181/mcp",
      "auth": {
        "CLIENT_ID": "...",
        "CLIENT_SECRET": "..."
      }
    }
  }
}
```

Redirect URI to add in the IdP client:

- `http://localhost:8787/callback`
- or `cursor://anysphere.cursor-mcp/oauth/callback` for older Cursor versions.

## Kiro (VS Code)

Config file: `~/.kiro/settings/mcp.json`

Example using `DCR` OAuth client registration:

```json
{
  "mcpServers": {
    "privx-mcp": {
      "url": "https://example-mcp.demo.net:8181/mcp"
    }
  }
}
```

Redirect URL: not needed with DCR.

## MCP Inspector

Configuration: Use the web UI at [http://localhost:6274/](http://localhost:6274/)

Streamable HTTP example using a static OAuth client:

```txt
# After clicking 'Add Servers' -> 'Add manually'

Server ID: privx-mcp
Transport: streamable-http
URL:       https://example-mcp.demo.net:8181/mcp

# After adding the server entry. Open server settings:

Client ID:     <OAuth client ID> (e.g. privx-mcp-client)
Client secret: The secret of the static client (created in the IdP)
Scopes:        openid profile email offline_access (assuming the IdP provides these)

```

Redirect URL: `http://localhost:6274/oauth/callback`

## OpenAI Codex

Config file: `~/.codex/config.toml`

Example using `DCR` OAuth client registration:

```toml
[mcp_servers.privx_mcp]
url = "http://localhost:8181/mcp"
```

Example using [privx-mcp-proxy](privx-mcp-proxy.md):

```toml
[mcp_servers.privx_mcp]
command = "/absolute/path/to/privx-mcp-proxy"
args = ["/absolute/path/to/privx-mcp-proxy.toml"]
```

## privx-mcp-proxy (stdio)

This works with Claude Code and other clients that support stdio MCP servers, although the JSON key names differ by client (`mcpServers` against `servers`, for example). [Codex](#openai-codex) uses TOML instead, as shown in the previous section.

Proxy configuration options: [privx-mcp-proxy](privx-mcp-proxy.md).

Example:

```json
{
  "mcpServers": {
    "privx-mcp": {
      "type": "stdio",
      "command": "/absolute/path/to/privx-mcp-proxy",
      "args": ["/absolute/path/to/privx-mcp-proxy.toml"]
    }
  }
}
```

## Known issues

### Client caching and PrivX roles

Most clients cache the MCP tool catalog, so the tool list goes stale when the signed-in user's PrivX roles change. Toggling the MCP server off and on or reauthenticating is sometimes enough, and some clients only refresh after a full restart. See [Role changes during an open session](../security/user_level_security.md#role-changes-during-an-open-session).
