# Okta

Configure Okta as the OAuth authorization server for the PrivX MCP server. Okta issues the tokens the MCP server validates. Part A is that authorization server and its OIDC app. Part B federates Okta to Microsoft Entra ID, so Entra authenticates the users and Okta still issues the token. Part C is the MCP server configuration, and it is the same either way.

One custom authorization server (the resource and audience) plus one OIDC app (the client) is enough.

## Part A — Okta configuration

### A1. Custom Authorization Server

`Security → API → Authorization Servers → Add Authorization Server`

| Field    | Value                                                                                                                               |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Name     | `PrivX MCP`                                                                                                                         |
| Audience | `https://<mcp-host>:<port>/mcp` — must equal the server's advertised resource exactly (scheme, host, port, path, no trailing slash) |
| Issuer   | auto-generated, e.g. `https://<org>.okta.com/oauth2/<authserver-id>`                                                                |

Note the **Issuer URI** — it becomes the server's `[oauth].issuer_url`.

### A2. Access Policy and Rule

`(authorization server) → Access Policies → Add Policy → Add Rule`

- Assign to: the OIDC app from A4 (or all clients)
- Grant type: `Authorization Code`
- Scopes: `openid`, `profile`, `email`, `offline_access`

### A3. Claims

`(authorization server) → Claims → Add Claim`

| Field                 | Value        |
| --------------------- | ------------ |
| Name                  | `email`      |
| Include in token type | Access Token |
| Value type            | Expression   |
| Value                 | `user.email` |
| Include in            | Any scope    |

This is the claim the MCP server reads for identity mapping (`identity_claim_field = "email"`).

### A4. OIDC Application (the client)

`Applications → Create App Integration → OIDC - OpenID Connect → Web Application`

| Field                 | Value                                                                                                          |
| --------------------- | -------------------------------------------------------------------------------------------------------------- |
| App name              | `privx-mcp-client`                                                                                             |
| Grant types           | Authorization Code + Refresh Token                                                                             |
| Sign-in redirect URIs | one per MCP client (see the client docs); for the mcp-remote bridge use `http://localhost:3334/oauth/callback` |
| Assignments           | assign the users/groups allowed to use the MCP server                                                          |

Record the **Client ID** and **Client Secret**.

## Part B — Federate to Microsoft Entra ID

Optional. Entra authenticates the users and Okta still issues the access token. PrivX resolves the same users as a [direct Entra](entra-id/ENTRA-ID.md) setup.

```
User → Okta sign-in → routing rule sends @your-domain users to Entra ID
     → Entra authenticates the user, returns claims to Okta
     → Okta issues its own access token (aud = MCP server)
     → MCP server verifies the token → mints a per-user PrivX JWT → per-user PrivX action
```

### B1. Entra App Registration (used by Okta)

`Azure Portal → App registrations → New registration`

| Setting                      | Value                                                                                                                                   |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Name                         | `Okta-Federation`                                                                                                                       |
| Supported account types      | **Multitenant** — required, because Okta's Microsoft IdP template calls Entra's `/common` endpoint, which single-tenant apps cannot use |
| Redirect URI (platform: Web) | Okta's callback, e.g. `https://<org>.okta.com/oauth2/v1/authorize/callback`                                                             |

Then, on the same app:

- **Certificates & secrets → New client secret** → copy the secret **Value**.
- **API permissions →** add delegated Microsoft Graph `openid`, `profile`, `email` **→ grant admin consent**.
- **Token configuration →** add `email` and `upn` as optional claims.

The Enterprise Application SSO blade and SAML configuration are not used; this is OIDC federation via the App Registration only.

### B2. Add Entra ID as an Identity Provider in Okta

`Security → Identity Providers → Add Identity Provider → Microsoft`

| Field              | Value                                                |
| ------------------ | ---------------------------------------------------- |
| Client ID / Secret | from the `Okta-Federation` app (B1)                  |
| Scopes             | `openid profile email`                               |
| Account link       | match on `email`; enable auto-link / JIT auto-create |

Copy the **Redirect URI** Okta generates and ensure it is registered on the Entra app (B1).

### B3. Routing rule (send users to Entra)

`Security → Identity Providers → Routing Rules → Add Routing Rule`

- IF user identifier matches `.*@<your-domain>`
- THEN use identity provider: `Microsoft Entra ID` (created in B2)
- Status: **Active**, prioritized above the default rule.

## Part C — MCP server configuration

```toml
[oauth]
issuer_url            = "https://<org>.okta.com/oauth2/<authserver-id>"
audience              = "https://<mcp-host>:<port>/mcp"   # equals the Okta authorization-server Audience
identity_claim_field  = "email"
identity_mapping_rule = "as-is"                            # or "strip-domain" to match PrivX usernames
dcr_stub_client_id     = "<okta-app-client-id>"            # for DCR-only clients (e.g. Kiro)
dcr_stub_client_secret = "<okta-app-client-secret>"
```

## Values that must align

| Value                | Set in                                                 | Must equal                                                           |
| -------------------- | ------------------------------------------------------ | -------------------------------------------------------------------- |
| Audience             | Okta authorization-server Audience and the token `aud` | server `[oauth].audience` (= advertised resource `{public_url}/mcp`) |
| Issuer               | Okta custom authorization-server issuer                | server `[oauth].issuer_url`                                          |
| Identity claim       | Okta access-token claim (`email`)                      | server `[oauth].identity_claim_field`                                |
| Redirect URI         | MCP client callback                                    | registered on the Okta OIDC app                                      |
| Entra federation app | Azure app registration                                 | Multitenant                                                          |

See [OIDC.md](OIDC.md) for the provider-agnostic overview and [entra-id/ENTRA-ID.md](entra-id/ENTRA-ID.md) for the direct-Entra setup.
