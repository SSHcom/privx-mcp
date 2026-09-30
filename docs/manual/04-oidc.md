# Configure OIDC

Set up one identity provider (IdP) so MCP clients can authenticate and the server can map each caller to a PrivX user. The steps are the same for every provider.

The [provider references](#provider-references) below show example setups for a few common IdPs. They are not complete guides: most providers, Microsoft Entra ID for example, can be set up in several ways, and we do not try to cover them all. You are expected to know your chosen IdP and adapt the examples to it.

## 1) Create a confidential client in the IdP

Create one confidential OAuth client per environment with authorization code flow (and refresh token where offered). Keep the issuer URL, client ID, and client secret for server and client configuration.

## 2) Register redirect URIs

Add a redirect URI for each MCP client you use. Take the exact values from [Redirect URIs](reference/clients/CLIENTS.md#redirect-uris) and keep hostnames exact, since `localhost` and `127.0.0.1` are different entries.

## 3) Match audience and identity claim

Access tokens must carry the audience set in `[oauth].audience`; without it, login succeeds but `/mcp` calls fail audience validation. The claim named by `[oauth].identity_claim_field` (typically `email` or `preferred_username`) must be present in the token.

## 4) Map identities to PrivX users

If the IdP identifier differs from the PrivX username, bridge the difference with `[oauth].identity_mapping_rule`. Set `[permissions].source_type` to the PrivX directory that holds those users.

## 5) Determine if you need the DCR stub

Some MCP clients require Dynamic Client Registration when connecting over HTTP. Entra ID and Okta expose no DCR endpoint for this use case, so when a client demands it, configure `[oauth].dcr_stub_client_id` and `dcr_stub_client_secret` on the server. Static client credentials are simpler to operate, so use the stub only when needed.

## 6) Validate end to end

Start the server, connect one MCP client, complete the browser login, and run one read tool call. If login succeeds but tools fail with permission or identity errors, or the tool list does not match the expected roles, check the identity claim mapping and `permissions.source_type`. If roles changed recently and the tool list looks stale, restart the client session.

## Provider References

- [OIDC Configuration overview](reference/oidc/OIDC.md)
- [Keycloak](reference/oidc/keycloak.md)
- [Microsoft Entra ID](reference/oidc/entra-id/ENTRA-ID.md)
- [Okta](reference/oidc/okta.md) - includes federating to Microsoft Entra ID

## Navigation

**Previous**: [Configure the server](03-configure.md)

**Next**: [Security and user operations](06-security-and-usage.md)

---

**Overview**: [Manual](README.md) | [Documents Hub](../README.md)
