# Security decisions

Product behaviour we inspected and chose not to change. Scanners read this before scoring ([security-scan.md](security-scan.md)).

- A match is not a defect unless the code no longer matches the entry.
- Operator hosting (TLS at a proxy, bind address, unauthenticated flood, secrets on disk) does not belong here; those are Notes in the scan report.
- When you accept a finding instead of fixing it, add an entry. When you later change that behaviour, delete or rewrite the entry in the same change.
- Keep entries newest first. On the same date, the most recently added entry comes first.

Each entry has a one-line summary, then **Behaviour**, **Accepted because**, and **Revisit if**.

## A cache miss searches the whole PrivX user directory

- Date: 2026-11-10
- Path: `internal/mcp/runtime/permissions.go`

Resolving an uncached caller reads every PrivX user and matches them in memory, because role-store search cannot express the match.

**Behaviour:**

- On a session cache miss, `resolveUserRoles` calls `SearchAllUsers` with an empty `UserSearch`.
- The token's email, UPN (`preferred_username`, else `upn`), and `sub` are matched: address-shaped values against `email` or `windows_account`, others against `principal`. `API-CLIENT` users are skipped, and exactly one user with `source_type` equal to `permissions.source_type` must remain.
- The hit, or `NotFound`, is cached by PrivX base URL, issuer, and `sub` for `session_cache_ttl`.

**Accepted because:**

- `UserSearch` only filters on `keywords`, `source` (directory id, not `source_type`), and `user_id`. A single `keywords` string cannot express three independent claims matched against different fields, and per-claim searches can miss users who match only on `windows_account`.
- Caching limits the full search to once per identity per TTL.

**Revisit if:**

- Role-store search can filter `email`, `principal`, `windows_account`, and `source_type`.
- A repeated call with the same issuer and `sub` searches the directory again before `session_cache_ttl` expires.

## Some tools are not gated by a PrivX permission

- Date: 2026-11-06
- Path: `internal/tools/permissions.go`, `internal/mcp/runtime/permissions.go`

Some tools are open to any authenticated caller or are not in the permission map at all. The map only decides which MCP tools a caller can see and call; every PrivX call runs as the caller, so PrivX still enforces their role permissions.

An ungated tool is a deliberate choice, not an oversight.

**Behaviour:**

- Tools in the `authenticated` scope are callable by anyone past `/mcp` bearer auth, with no PrivX permission lookup.
- Examples: `mcp-info` describes this server and the caller's session, and no PrivX permission matches it. `host-search` does not require `hosts-view`, because PrivX lets users search the hosts they are connected to without it; PrivX returns only hosts that user may see.

**Accepted because:**

- A mapping cannot let a caller see or do more than their PrivX role allows.
- Requiring a resource permission would hide general tools, or data the user can already reach in PrivX, from callers without that scope.

**Revisit if:**

- A tool call no longer runs as the signed-in user.
- An ungated tool returns data the caller's PrivX role does not allow, or does not call PrivX as that user.

## m2m and m2m-jwt trust shared secrets plus mapper

- Date: 2026-11-04
- Path: `internal/auth/m2m/verifier.go`, `internal/auth/m2m/jwt_verifier.go`, `internal/mcp/transport/auth_challenge.go`, `internal/config/m2m_jwt.go`

Both machine-to-machine modes are only as secure as their shared secrets.

**Behaviour:**

- `m2m`: `Authorization: Bearer <secret>` is matched against configured secret-to-user mapper rows.
- `m2m-jwt`: `X-API-KEY` is matched, then JWT claims map to a user. The JWT signature is not checked; `exp` is required and `iss` is checked when configured.
- Only explicitly mapped users are reachable; unmapped identities are rejected.

**Accepted because:**

- In shielded and black-box deployments `m2m-jwt` cannot assume access to a signing authority, so the API key is the security boundary and the JWT only routes claims.
- Static header credentials between trusted components are common in MCP deployments.
- Mapper rows limit the blast radius, and these modes are not meant for end-user authentication.

**Revisit if:**

- Signature verification in `m2m-jwt` becomes a requirement.
- A default-safe local-key or JWKS verification path becomes available for target deployments.
- These modes must support end users.

## A failed JWKS refresh keeps the last signing keys

- Date: 2026-09-25
- Path: `internal/auth/oauth/verifier.go`

When a background JWKS refresh fails, tokens keep verifying against the last successfully fetched keys, and the failure is logged.

**Behaviour:**

- `NewJWKSTokenVerifier` refreshes on `oauth.jwks_cache_ttl` (default one hour).
- `RefreshErrorHandler` logs a warning with the JWKS URI and error and keeps the current key set.
- Startup fails if the first JWKS fetch fails.
- The key set is in memory only; a restart drops it.

**Accepted because:**

- A key the IdP removed can verify a forged token only if the attacker holds its private key, refresh is still failing, and the token passes signature, issuer, audience, and expiry checks with an identity claim that resolves to a PrivX user. The IdP holds the private key, so this requires a compromised IdP or IdP host.
- Dropping the keys after a failed refresh would turn an IdP or network outage into refusing every login until the endpoint recovers.

**Revisit if:**

- Refresh is triggered by an unknown `kid` (`RefreshUnknownKID`), so bad tokens can drive extra fetches.
- The IdP requires a removed key to stop verifying immediately, even while refresh is down.

## A closed privx-admin window still allows every tool

- Date: 2026-09-25
- Path: `internal/mcp/runtime/permissions.go`

A `privx-admin` user still sees and can call every tool while that role's time window is closed; PrivX rejects the action, so the call fails.

**Behaviour:**

- `hasRequiredPermissionsAt` returns early when `hasPrivxAdminRole` finds a role named `privx-admin` (name match only).
- Other roles go through `isRoleWindowAllowed`, which drops them outside their weekday or daily window; `activeRoles` applies the same window for handler-side membership. The admin bypass skips both.

**Accepted because:**

- The call runs as the user through an external JWT, and PrivX enforces the role's contextual limits.
- A local filter would only fail earlier with a clearer error, using role context cached on `ResolvedRoles` for `session_cache_ttl`.
- Hiding tools is unreliable: clients that keep their own catalog ignore list-change signals, and the MCP Go SDK cannot send `tools/list_changed` to a single session.
- The call result already returns `not_authorized` or `roles_changed`.

**Revisit if:**

- A tool call no longer runs as the user.
- A closed window lets a PrivX API call succeed.

## Permission user and connector user are matched once per session

- Date: 2026-09-25
- Path: `internal/mcp/runtime/access.go`, `internal/service/session/service.go`

Each tool call involves two PrivX users that must be the same person. The first call checks this; later calls reuse the cached result.

**Behaviour:**

- Permission user (whose roles decide allowed tools): a directory search on the token's email, UPN, and subject, limited to `permissions.source_type`.
- Connector user (who PrivX sees making the call): the `oauth.identity_claim_field` claim (default `email`), mapped to a username, minted into an external JWT, and exchanged with PrivX.
- On the first call the runtime loads the connector's current user and refuses the call unless its id equals the permission user's id.
- A match is cached by PrivX base URL, token issuer, and `sub`.

**Accepted because:**

- `sub` and the mint claim come from the same bearer token, so they stay fixed until the IdP issues a new token.
- A different person has a different `sub` and is checked again.
- An email change in PrivX during a login goes unnoticed only until `session_cache_ttl` expires.

**Revisit if:**

- One token subject can reuse another subject's cached match.
- A cache miss no longer runs the live user-id check.

## echo is always registered

- Date: 2026-09-16
- Path: `internal/tools/echo`, `internal/tools/register.go`

Any identity past `/mcp` bearer auth can call `echo`, a hello-world probe that replies `dummy: <message>` without touching PrivX.

**Behaviour:**

- `Register` always mounts it.
- `RequiredPermissions` is empty.
- It is not `Trusted`, so inbound hardening still applies.
- Product docs omit it on purpose.

**Accepted because:** it has no side effects and exposes nothing beyond the caller's own input.

**Revisit if:** we decide to hide it in production (add a config flag then).
