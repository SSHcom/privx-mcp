# Microsoft Entra ID

The Entra ID apps and the matching MCP server configuration.

## Related documents

- [OIDC configuration](../OIDC.md)
- [Entra auth flow diagram](auth-flow.md)
- [Keycloak](../keycloak.md)
- [Okta](../okta.md) when Okta issues the tokens and Entra authenticates the users
- [MCP server configuration](../../server/SERVER.md)
- [MCP client configuration](../../clients/CLIENTS.md)

## Entra ID apps

Connecting one MCP client to one MCP server needs **two** Entra ID apps: a resource app representing the MCP server, and a client app representing the MCP client. The access token has to name both, the resource in `aud` and the client in `appid` / `azp`.

Two apps are a constraint, not a preference:

1. **Entra refuses to issue a token where the requester and the destination are the same app when the destination is identified by a URL.** An app may request a token for itself only with a GUID identifier. MCP clients take `resource` from the server's [RFC 9728 metadata](../OIDC.md#how-the-server-advertises-itself), which is a URL such as `https://example-mcp.demo.net:8181/mcp`, so a single app fails with `AADSTS90009: Application is requesting a token for itself.`
2. **The resource identifier must be a verified domain or `api://<client-id>`,** and MCP clients require it to match the server URL. For local `http://localhost`, use a single-tenant app.
3. **The token audience is the resource, not the client.** This is plain OAuth, where the client acts on behalf of the user to reach the API.

Two apps do not mean two logins. The user signs in once, and the second app is bookkeeping inside Entra. See the [Entra auth flow diagram](auth-flow.md) for the full sequence.

> <p>&nbsp;</p>
> <div style="text-align: center;">
>   <image src="../../../../../.md-images/entraid-oidc-flow.png" width="400">
> </div>
> <p>&nbsp;</p>
>
> - **Client app** (`example-mcp-client`): the MCP client asking for the token. The user signs in once through it, using PKCE.
> - **Resource app** (`EXAMPLE-MCP`): the MCP server the token is meant for.
> - `**aud**`: the token audience, set to the resource app's Application ID URI (e.g. `https://example-mcp.demo.net:8181/mcp`). The server rejects tokens where it does not match `[oauth].audience`.
> - `**appid` / `azp**`: the client app that requested the token.
> - `**upn**`: the signed-in user (`user@domain`). The server acts in PrivX as this user.
> - **Bearer on /mcp**: the client sends the token in the `Authorization: Bearer` header on every `/mcp` request.
> <p>&nbsp;</p>

### What each app is for

|               | Resource app `EXAMPLE-MCP`                          | Client app `example-mcp-client`                 |
| ------------- | --------------------------------------------------- | ----------------------------------------------- |
| Represents    | The MCP server (the protected thing)                | The MCP client / IDE (the asking thing)         |
| Answers       | "What are you trying to reach?"                     | "Who is doing the asking?"                      |
| In the token  | `aud` (audience)                                    | `appid` / `azp`                                 |
| Its job       | Defines Application ID URI + `access_as_user` scope | Holds secret, runs browser login, gets consent  |
| Server config | `[oauth].audience`                                  | `dcr_stub_client_id` / `dcr_stub_client_secret` |

Three values must be identical: `[oauth].audience`, the resource app's Application ID URI, and the `resource` the server advertises (`server.public_url` with `/mcp` appended). The DCR stub credentials are the client app's, not the resource app's.

## Creating the apps

Create both apps in the Entra admin center under `App registrations → New registration`.

### Resource app

| Setting                 | Value                                                                  |
| ----------------------- | ---------------------------------------------------------------------- |
| Name                    | e.g. `EXAMPLE-MCP`                                                     |
| Supported account types | Single tenant                                                          |
| Application ID URI      | Must match `[oauth].audience` (typically `server.public_url` + `/mcp`) |
| Expose an API           | Delegated scope, e.g. `access_as_user`                                 |

### Client app

| Setting                 | Value                                             |
| ----------------------- | ------------------------------------------------- |
| Name                    | e.g. `example-mcp-client`                         |
| Supported account types | Single tenant                                     |
| Authentication platform | Web, plus Mobile/Desktop if you use loopback      |
| Client secret           | For clients that send a confidential `auth` block |
| API permissions         | Delegated: resource app → `access_as_user`        |
| Admin consent           | Grant for the tenant                              |

### How Entra allow-lists redirect URIs

Redirect URIs are defined by the MCP client. Take them from [MCP client configuration](../../clients/CLIENTS.md#redirect-uris) and register each one you use on the client app.

One Entra-specific shortcut is worth knowing. On the Mobile and desktop applications platform, `http://localhost/oauth/callback` matches **any port**, so one entry can cover several loopback clients without listing each port. It does not change the URI the client actually sends.

`localhost` and `127.0.0.1` are still different hosts. Hosted HTTPS callbacks must be listed as that exact URI on a Web platform.

## MCP server configuration

### Stub Dynamic Client Registration

Entra ID does not implement DCR (RFC 7591), so clients that only support dynamic registration, such as Kiro, cannot authenticate against it directly. Enable the [DCR stub](../OIDC.md#dynamic-client-registration-dcr) with the client app's credentials. The stub hands them out on `/register` and injects a `registration_endpoint` into the proxied Entra discovery document.

```toml
[oauth]
dcr_stub_client_id = "5b2abfe7-..."
dcr_stub_client_secret = "your-secret"
```

### Identity claims

Azure v1 tokens (`"ver": "1.0"`) have no `email` claim, so map the identity from `upn` instead:

```toml
[oauth]
identity_claim_field = "upn"
identity_mapping_rule = "as-is"
```

### Example `privx-mcp-config.toml`

Clients derive the token scope `{resource}/.default` from the advertised `resource`, so `[oauth].audience` below is the resource app's Application ID URI.

```toml
[server]
name = "privx-mcp-server"
version = "dev"
public_url = "https://example-mcp.demo.net:8181"
tls_cert_file = "/path/to/mcp-tls-cert.pem"
tls_key_file = "/path/to/mcp-tls-key.pem"

[privx_auth]
privx_base_url = "https://privx.example.com"
rsa_key_file = "/path/to/privx-mcp-signing-key.pem"
rsa_key_id = "privx-mcp-key-1"
audience = "privx-mcp-client"
token_issuer = "privx-mcp"
subject_format = "plain"
api_oauth_client_id = "privx-external"
api_oauth_client_secret = "..."
api_client_id = "..."
api_client_secret = "..."

[permissions]
default_read_only = true
whitelist = ["host-", "user-", "workflow-", "test-"]
session_cache_ttl = "30s"

[oauth]
issuer_url = "https://sts.windows.net/{tenant-id}/"
audience = "https://example-mcp.demo.net:8181/mcp"
scopes = ["openid", "profile", "email", "offline_access"]
identity_claim_field = "upn"
identity_mapping_rule = "as-is"
dcr_stub_client_id = "5b2abfe7-..."
dcr_stub_client_secret = "..."
```
