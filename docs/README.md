# PrivX MCP documentation

The PrivX MCP server speaks streamable HTTP at `/mcp`, with no SSE transport. In `oauth` mode, MCP clients authenticate with an OIDC access token. In `m2m` mode, a machine client sends a configured service secret as a bearer. The server verifies the caller, resolves a PrivX user, and runs tools as that user.

An unauthenticated POST to `{public_url}/mcp` returns `401`, which points the client at RFC 9728 discovery on `/.well-known/oauth-protected-resource`. The client then sends the user to the OIDC issuer for browser sign-in and retries `/mcp` with the resulting Bearer token. See [OIDC configuration](manual/reference/oidc/OIDC.md) for token validation and identity mapping details. An `m2m` server does not publish that discovery document. The client must already hold the secret. See [Configure machine-to-machine access](manual/04-m2m.md).

Prefer the client's native HTTP OAuth flow when it works. Clients that only start local stdio processes can use [privx-mcp-proxy](manual/reference/clients/privx-mcp-proxy.md) as a bridge.

## Documentation

- [Manual](manual/README.md)
- [Reference](manual/reference/README.md)
- [Development](development/DEVELOPMENT.md)

## Diagrams

Interactive architecture and tool call diagrams live in [Diagrams](diagrams/) and open in a browser.
