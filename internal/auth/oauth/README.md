# `internal/auth/oauth`

OIDC primitives used by the PrivX MCP server to verify bearer JWTs that MCP
clients send to `/mcp`.

The MCP server is a **resource server**, not an OAuth client. MCP clients
(Cursor, etc.) perform the OIDC authorization-code + PKCE dance with the
upstream IdP themselves — they discover the IdP via the RFC 9728 metadata
served at `/.well-known/oauth-protected-resource` (see the `wellknown/`
subpackage), then send the resulting JWT to `/mcp` as
`Authorization: Bearer <jwt>`. This package provides only the parts the MCP
server itself needs: discovery, JWKS-based verification, and claim mapping.

---

## Package layout

```
oauth/
├── discovery.go          OIDC discovery document fetch
├── verifier.go           JWKS-based bearer-token verification
├── mapper.go             IdP claims → PrivX username
└── wellknown/
    └── protected_resource.go   RFC 9728 protected-resource metadata
```

---

## MCP bearer-token path

```
MCP client → /mcp  Authorization: Bearer <jwt>
              │  JWKSTokenVerifier.Verify(token)   ← long-lived, started at bootstrap
              │  → IdentityClaims { sub, email, upn, iss, aud, raw_claims }
              └► privx.ConnectWithExternalJWT(claims)
```

`JWKSTokenVerifier` enforces `iss`, `aud`, signature, and `exp` on every
incoming JWT. The expected `aud` comes from `oauth.audience` in
the TOML config.

The 401 challenge that triggers discovery is implemented in
`internal/mcp/transport/auth_challenge.go`; the RFC 9728 metadata handler
lives in `internal/auth/oauth/wellknown/protected_resource.go`.

---

## Key types

### `HTTPDiscoveryClient`

Fetches `{issuer}/.well-known/openid-configuration`. The bootstrap path uses
it only to read `jwks_uri` (required) and `issuer` (optional normalization).
Used by `buildIdentityVerifier` to auto-resolve the JWKS URI when
`oauth.jwks_uri` is not set.

### `IdentityTokenVerifier`

Validates an RS256/ES256 JWT against the provider JWKS. Checks issuer,
audience, and expiry. Returns `IdentityClaims` containing `sub`, `email`,
`upn`, `iss`, and `aud`. JWKS keys are refreshed on a configurable interval
(default 1 h).

### `IdentityMapper`

Maps verified token claims to a plain username string used downstream for
PrivX authentication.

`identity.claim_field` is resolved against raw token claims.
Supported syntax includes plain keys (`email`, `preferred_username`) and dot
notation with array indexes (`resource_access.account.roles[0]`).

| `mapping_rule`    | Transform             |
| ----------------- | --------------------- |
| `strip-domain`    | local part before `@` |
| `as-is` (default) | value unchanged       |

---

## Configuration

Settings live under `[oauth]` and `[identity]` in the TOML config.

| Field                  | Purpose                                                                        |
| ---------------------- | ------------------------------------------------------------------------------ |
| `oauth.issuer_url`     | OIDC issuer URL (used for discovery and as expected `iss`)                     |
| `identity.claim_field` | Claim path used for identity mapping (supports dot notation and array indexes) |
| `oauth.scopes`         | Scopes to advertise (informational; MCP clients choose their own)              |
| `oauth.audience`       | Expected `aud` claim on bearer JWTs sent to `/mcp`                             |
| `oauth.jwks_uri`       | JWKS URI override; auto-discovered from issuer if omitted                      |
| `oauth.jwks_cache_ttl` | How long to cache JWKS keys; default `1h`                                      |

---

## Security notes

- JWKS key rotation is handled automatically at the configured cache TTL.
- Audience validation is enforced on every verified token. A mismatch
  surfaces as a `wrong_audience` `VerificationError` and propagates up
  through `Authenticate` to the MCP tool call result.
- The MCP server holds no OAuth client secret. It never exchanges
  authorization codes; that is the MCP client's responsibility.
