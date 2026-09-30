# `internal/auth/privx`

Establishes an authenticated PrivX SDK client for an incoming MCP request using the **External JWT Authentication** pattern.

After an IdP bearer token has been verified by `internal/auth/oauth`, the `privx` package takes the resulting identity claims and produces a `restapi.Connector` that tools can use to call PrivX APIs. It owns three steps: claim-to-username mapping, JWT minting, and PrivX token exchange.

---

## How it fits into the auth flow

```
IdP bearer token (verified by oauth.JWKSTokenVerifier)
        │
        ▼  IdentityClaims { sub, email, upn, … }
ConnectWithExternalJWT(cfg, claims)
        │
        ├─ 1. Map claims → PrivX username
<<<<<<< HEAD
        │       oauth.IdentityMapper (claim_field + mapping_rule)
=======
        │       oauth.IdentityMapper (identity.claim_field + mapping_rule)
>>>>>>> oidc-support
        │
        ├─ 2. Mint external JWT
        │       RS256, signed with local RSA key
        │       iss = cfg.Auth.TokenIssuer  (default "privx-mcp")
        │       sub = username  (or "CN=username" for DN format)
        │       exp = now + 90s
        │       kid = cfg.Auth.RSAKeyID
        │
        └─ 3. Exchange JWT with PrivX
                POST {privx_base_url}/auth/api/v1/token/login
                ← PrivX access token
                ← restapi.Connector (authenticated SDK client)
```

The connector is returned to `auth.Authenticator`, stored in the MCP request context, and used by every tool in the request.

---

## External JWT Authentication

PrivX supports trusting a third-party JWT issuer for login. The MCP server acts as that trusted issuer:

1. An RSA key pair is generated and the **public key is registered in PrivX** (Admin → External Token Authentication) together with the `iss` claim value and an optional `kid`.
2. For each MCP request the server mints a short-lived JWT (90 s) signed with the private key and sends it to PrivX's token endpoint.
3. PrivX validates the JWT signature and claims, then returns its own access token.

Because the minted JWT is so short-lived it is not cached — a fresh exchange happens on every authenticated MCP request.

---

## Package layout

```
privx/
├── connect.go      ConnectWithExternalJWT — orchestration entry point
├── minter.go       JWTMinter — RSA JWT creation
└── exchanger.go    TokenExchanger — PrivX token exchange + error types
```

### `JWTMinter`

Reads a PEM file at startup (PKCS#1 `RSA PRIVATE KEY` or PKCS#8 `PRIVATE KEY`). `Mint(username)` returns a signed JWT. The `sub` claim is plain by default; set `subject_format = "dn"` to emit `CN=<username>` for PrivX environments that use DN-style subjects.

### `TokenExchanger`

Wraps `privx-sdk-go/oauth.WithExchangeToken`. Calls `AccessToken()` eagerly before returning the connector so that auth errors (wrong issuer, unknown key, revoked user) surface at authentication time rather than on the first tool call.

### Error types

| Type                | Meaning                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `ExchangeAuthError` | PrivX rejected the identity — 401/403 or invalid-grant responses |
| `NetworkError`      | Could not reach PrivX — DNS, connection refused, timeouts        |

The MCP runtime maps these to user-visible error messages:
- `ExchangeAuthError` → `"authentication failed: PrivX rejected the user identity"`
- `NetworkError` → `"connectivity failure: unable to reach PrivX"`

---

## Configuration

All fields are under `[auth]` in the TOML config.

| Field                | TOML key          | Default        | Purpose                                                         |
| -------------------- | ----------------- | -------------- | --------------------------------------------------------------- |
| RSA private key path | `rsa_key_file`    | (required)     | Key used to sign minted JWTs                                    |
| Key ID               | `rsa_key_id`      | (required)     | `kid` header; must match PrivX config                           |
| Token issuer         | `token_issuer`    | `"privx-mcp"`  | `iss` claim; must match PrivX config                            |
| PrivX base URL       | `privx_base_url`  | (required)     | Token exchange endpoint base                                    |
<<<<<<< HEAD
| Exchange scope       | `exchange_scope`  | `"privx-user"` | OAuth scope sent to PrivX                                       |
| OAuth client ID      | `oauth_client_id` | —              | Optional `client_id` for PrivX token request                    |
| Subject format       | `subject_format`  | `"plain"`      | `"plain"` or `"dn"`                                             |
| PrivX audience       | `audience`        | —              | `aud` claim in minted JWT; must match PrivX External IdP config |

Identity mapping (claim field and rule) is configured under `[identity]` — see `internal/auth/oauth` for details.
=======
| Subject format       | `subject_format`  | `"plain"`      | `"plain"` or `"dn"`                                             |
| PrivX audience       | `audience`        | —              | `aud` claim in minted JWT; must match PrivX External IdP config |

Identity mapping uses `identity.claim_field` and `identity.mapping_rule` — see `internal/auth/oauth` for details.
>>>>>>> oidc-support

---

## PrivX setup checklist

**TO BE UPDATED** - We need to better describe the PrivX External JWT configuration


1. Generate an RSA key pair (2048-bit or stronger).
2. In PrivX Admin → **External Token Authentication**:
   - Add the public key (PEM).
   - Set the issuer to match `token_issuer` (default `privx-mcp`).
   - Set the key ID to match `rsa_key_id`.
3. Configure `rsa_key_file` to point to the private key on the MCP server.
<<<<<<< HEAD
4. Ensure PrivX usernames match the values produced by the configured `claim_field` + `mapping_rule`.
=======
4. Ensure PrivX usernames match the values produced by the configured `identity.claim_field` + `mapping_rule`.
>>>>>>> oidc-support
