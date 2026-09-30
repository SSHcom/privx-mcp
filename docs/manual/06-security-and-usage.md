# Server security and user operations

Security is layered. Each area below covers one layer, from the network in front of the server to the PrivX roles behind it.

## Deployment

Serve the MCP server over HTTPS, either with TLS enabled in the server itself or behind a reverse proxy that terminates TLS. Bearer tokens and service secrets travel in every request, so plain HTTP is only acceptable on localhost. Run a single shared remote server for production PrivX, and keep its key pair and API credentials on that server only.

Read more: [TLS (HTTPS)](reference/server/tls.md), [Deploy the MCP server remotely in production](reference/security/security.md#deploy-the-mcp-server-remotely-in-production)

## MCP server configuration

The server configuration decides which tools exist at all, for every user, before any PrivX role is considered.

- **Read-only mode** removes every tool that changes PrivX. It is on by default, and should stay on until you have decided which write tools to allow.
- **Whitelist and blacklist** narrow the tool set further by tool name, for example to expose only access-request tools.
- **Rate limiting** caps how many tool calls one identity can make in a time window, with an optional extra cooldown after a maxed-out window. This stops a looping model or a misbehaving client from hammering PrivX and the server.

Read more: [Which tools are registered](reference/security/user_level_security.md#which-tools-are-registered), [Loop and DDoS protection](reference/security/security.md#loop-and-ddos-protection)

## MCP server internal hardening

Text stored in PrivX, such as host comments and role descriptions, reaches the language model as-is, so it could carry injected instructions. The server treats all PrivX data and all client input as untrusted:

- Invisible and control characters are stripped from every string.
- A word blacklist is applied to both requests and responses. A request containing a blocked word is rejected and the word is named. A response containing one is withheld, or for list and search results only the offending rows are dropped.
- Every successful response is wrapped in an envelope that tells the model the content is data, not instructions.

This raises the cost of an attack but cannot block it fully, so the permissions below remain the real boundary.

Read more: [Prompt injection hardening](reference/security/security.md#prompt-injection-hardening), [What the hardening cannot do](reference/security/security.md#what-the-hardening-cannot-do)

## PrivX

Every tool call runs as the authenticated PrivX user. Their PrivX roles, and the permissions those roles carry, decide which of the registered tools they see and can call. Tools a user cannot call are hidden from their tool list. Every permission granted is one the model can exercise on the user's behalf, so grant only what you would trust that person to do directly.

When a user's roles change, some clients keep showing a stale tool list until the client application is restarted.

Tool responses drop credential and key material before they reach the client, including when `raw` is set. Identity fields such as email and principal stay.

Read more: [User-level security](reference/security/user_level_security.md), [Permissions and trust](reference/security/security.md#permissions-and-trust), [Redacted fields](reference/security/redacted_fields.md), [MCP tools](reference/user/tools.md)

## Navigation

**Previous**: 
- [Configure OIDC](04-oidc.md)
- [Configure machine-to-machine access](04-m2m.md)

---

**Overview**: [Manual](README.md) | [Documents Hub](../README.md)
