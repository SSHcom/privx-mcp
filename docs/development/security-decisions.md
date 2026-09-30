# Security decisions

Product behaviour we inspected and chose not to change. Scanners read this before scoring ([security-scan.md](security-scan.md)).

- A match is not a defect unless the code no longer matches the entry.
- Operator hosting (TLS at a proxy, bind address, unauthenticated flood, secrets on disk) does not belong here; those are Notes in the scan report.
- When you accept a finding instead of fixing it, add an entry. When you later change that behaviour, delete or rewrite the entry in the same change.
- Keep entries newest first. On the same date, the most recently added entry comes first.

Each entry has a one-line summary, then **Behaviour**, **Accepted because**, and **Revisit if**.

## A failed JWKS refresh keeps the last signing keys

- Date: 2026-09-25
- Path: `internal/auth/oauth/verifier.go`

When a background JWKS refresh fails, tokens keep verifying against the keys from the last successful fetch. The failure is logged.

**Behaviour:**

- `NewJWKSTokenVerifier` refreshes on `oauth.jwks_cache_ttl` (default one hour).
- `RefreshErrorHandler` logs a warning with the JWKS URI and the error, and leaves the current key set in place.
- Startup still refuses to start if the first JWKS fetch fails.
- The key set is in memory only. A process restart drops it.

**Accepted because:**

- A key the IdP has removed still verifies a forged token only when the attacker holds that key's private key, JWKS refresh is still failing so this process has not loaded the removal, and the token passes signature, issuer, audience, and expiry checks with an identity claim that resolves to a PrivX user. The private key is held by the identity provider, so this starts from a compromised IdP or IdP host.
- Dropping the keys after a failed refresh would make an IdP or network outage refuse every login until the endpoint answers again.

**Revisit if:**

- Refresh starts on an unknown `kid` (`RefreshUnknownKID`), so bad tokens can drive extra fetches.
- The IdP requires a removed key to stop verifying immediately, including while refresh is down.

## A closed privx-admin window still allows every tool

- Date: 2026-09-25
- Path: `internal/mcp/runtime/permissions.go`

A user with the `privx-admin` role still sees and can call every tool while that role's time window is closed. PrivX rejects the action, so the call fails.

**Behaviour:**

- `hasRequiredPermissionsAt` returns immediately when `hasPrivxAdminRole` finds a role named `privx-admin`. It compares the name only.
- Other roles go through `isRoleWindowAllowed`, which drops them when their weekday or daily window is closed; `activeRoles` uses the same window for handler-side membership. The admin bypass skips this.

**Accepted because:**

- The call runs as that user through an external JWT, and PrivX enforces the role's contextual limits.
- A local filter would only fail earlier with a clearer error, based on role context cached on `ResolvedRoles` for `session_cache_ttl`.
- Hiding the tools would not help reliably: clients that keep their own catalog ignore list-change signals, and the MCP Go SDK cannot send `tools/list_changed` to one session only.
- The call result already returns `not_authorized` or `roles_changed`.

**Revisit if:**

- A tool call no longer runs as the user.
- A closed window lets a PrivX API call succeed.

## Permission user and connector user are matched once per session

- Date: 2026-09-25
- Path: `internal/mcp/runtime/access.go`, `internal/service/session/service.go`

Each tool call involves two PrivX users that must be the same person. The first call confirms it; later calls reuse the cached result.

**Behaviour:**

- Permission user (whose roles decide which tools are allowed): a directory search on the token's email, UPN, and subject, limited to `permissions.source_type`.
- Connector user (who PrivX sees making the API call): the `oauth.identity_claim_field` claim (default `email`), mapped to a username, minted into an external JWT, and exchanged with PrivX.
- On the first call the runtime loads the connector's current user and refuses the call unless its id equals the permission user's id.
- A match is cached under the PrivX base URL, the token issuer, and `sub`.

**Accepted because:**

- `sub` and the mint claim come from the same bearer token, so they stay fixed until the IdP issues a new token.
- A different person has a different `sub` and is checked again.
- An email change in PrivX during a login stays unnoticed only until `session_cache_ttl` expires.

**Revisit if:**

- One token subject can reuse another subject's cached match.
- A cache miss no longer runs the live user-id check.

## echo is always registered

- Date: 2026-09-16
- Path: `internal/tools/echo`, `internal/tools/register.go`

Any identity that passed `/mcp` bearer auth can call `echo`. It is a hello-world probe that replies `dummy: <message>` and does not touch PrivX.

**Behaviour:**

- `Register` always mounts it.
- `RequiredPermissions` is empty.
- It is not `Trusted`, so inbound hardening still applies.
- Product docs omit it on purpose.

**Accepted because:** it has no side effects and exposes nothing beyond the caller's own input.

**Revisit if:** we decide to hide it in production (add a config flag then).
