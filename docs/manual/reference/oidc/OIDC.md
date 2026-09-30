# OIDC configuration

MCP clients authenticate against your own identity provider (IdP). The MCP server never sees a password. It validates the OIDC access token the client presents on `/mcp`, maps a claim in that token to a PrivX user, and runs tools as that user.

## Related documents

- [MCP server configuration](../server/SERVER.md)
- [MCP client configuration](../clients/CLIENTS.md)
- [privx-mcp-proxy](../clients/privx-mcp-proxy.md)

## Provider guides

- [Keycloak](keycloak.md)
- [Microsoft Entra ID](entra-id/ENTRA-ID.md), with the [Entra auth flow diagram](entra-id/auth-flow.md)
- [Okta](okta.md), including federation to Microsoft Entra ID

Any standards-compliant OIDC provider works. The guides above differ only in how the provider is configured.

## What the server needs from the IdP

| Requirement          | Config                                                  | Notes                                                                                              |
| -------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Issuer               | `[oauth].issuer_url`                                    | The discovery document must be reachable from the server, and JWKS is fetched from it.             |
| Audience             | `[oauth].audience`                                      | Must equal the `aud` claim of the access token. Some providers only add it via an explicit mapper. |
| Identity claim       | `[oauth].identity_claim_field`, `identity_mapping_rule` | Resolves the token to a PrivX principal, for example `email` with `as-is`.                         |
| Client registrations | at the IdP                                              | One confidential OIDC client per deployment is usually enough for all MCP clients.                 |

Parameter reference: [MCP server configuration](../server/SERVER.md#oauth).

## Redirect URIs

Redirect URIs are decided by the **MCP client**, not by the IdP or this server. The IdP only allow-lists the URI the client sends. Take the values from [MCP client configuration](../clients/CLIENTS.md#redirect-uris) and register only the ones you actually use.

## How the server advertises itself

The server publishes RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource`, so a client that gets a `401` from `/mcp` can discover the issuer on its own:

```json
{
  "resource": "https://example-mcp.demo.net:8181/mcp",
  "authorization_servers": ["https://example-mcp.demo.net:8181"]
}
```

`resource` is `server.public_url` with `/mcp` appended.

## Dynamic Client Registration (DCR)

Some MCP clients only support Dynamic Client Registration (RFC 7591) and refuse to take a static `client_id` and `client_secret` from their config file. When the IdP does not implement DCR, set `[oauth].dcr_stub_client_id` and `dcr_stub_client_secret`. The server then exposes `/register`, which hands out your pre-configured client credentials, and proxies `/.well-known/oauth-authorization-server` with a `registration_endpoint` injected.

Providers that implement DCR natively, such as Keycloak with client registration enabled in the realm, do not need the stub.
