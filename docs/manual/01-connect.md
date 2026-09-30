# Connect to an already running server

Use this page the MCP server is already deployed and you only need to point an MCP client at it, complete OAuth, and call tools over `/mcp`.

For an `m2m` deployment, follow [Configure machine-to-machine access](04-m2m.md).

## Prerequisites

- You know the server base URL, for example `https://mcp.example.net:8181`.
- The MCP server is reachable from your machine.
- An IdP client exists for this environment, including your client callback URI.
- You have a PrivX user that matches your IdP identity according to the server mapping.

## 1) Confirm server reachability

Before opening the MCP client, verify that `/mcp` responds and OAuth discovery is available:

```bash
curl -i https://mcp.example.net:8181/mcp
curl -s https://mcp.example.net:8181/.well-known/oauth-protected-resource
```

Expect `401` from `/mcp` before login and a JSON discovery document from `/.well-known/oauth-protected-resource`.

## 2) Connection method and client configuration

Pick a method or client type from the table, then follow the section for your client in [MCP client configuration](reference/clients/CLIENTS.md).
| Method / Client type | Use when |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Generic MCP client (Claude, Codex, Cursor, etc.) | The client supports HTTP streaming and OAuth authentication |
| [privx-mcp-proxy](reference/clients/privx-mcp-proxy.md) | The client only starts local stdio processes, or the client page recommends the proxy |
| MCP proxy or gateway | Extra policy, routing, isolation, or logging already sits in front of this server |

**Note**: In principle a proxy or gateway will be configured like a generic MCP client. How a generic client will connect to a proxy or gateway is beyond the scope of this documentation.

## 3) Complete first OAuth login

On first connect, most clients open a browser. Sign in with the same identity that should map to your PrivX user. If login succeeds but tool calls fail, the cause is usually server-side identity mapping or the PrivX user directory source. See [Configure the server](03-configure.md).

## 4) Validate a tool call

Run one safe read operation, for example `mcp-info`, `host-list`, or `host-search`, and confirm you get data rather than an auth error.

If the client still shows stale tools after role changes, restart the client or reconnect to refresh the tools list. See [known issues](reference/clients/CLIENTS.md#known-issues) in the client configuration reference.

## Navigation

**Next**: [Installation](02-install.md)

---

**Overview**: [Manual](README.md) | [Documents Hub](../README.md)
