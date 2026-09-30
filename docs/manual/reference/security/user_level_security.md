# User-level security

How the PrivX MCP server decides **which tools a user can see** and **which tools they can call**. The same permission rules apply in both cases, so a client should never see a tool it cannot invoke.

## Related documents

- [Security considerations](security.md)
- [MCP tools](../user/tools.md)
- [User documentation](../user/USER.md)
- [MCP server configuration](../server/SERVER.md)
- [PrivX configuration](../server/privx.md)
- [Configure machine-to-machine access](../../04-m2m.md)

## Overview

Access control has three layers:

1. **Who is calling?** The server identifies the user from an OAuth token or, in `m2m` mode, from a configured service secret.
2. **Which tools exist for this deployment?** Server config can hide write tools or limit tools by name prefix before anyone connects.
3. **What may this user do in PrivX?** The user's PrivX roles and permissions decide which remaining tools are visible and callable.

Layers 1 and 3 are evaluated per user. Layer 2 is global for the server process.

```
MCP client
    |
    |  OAuth bearer token, or a service secret in m2m mode
    v
MCP server
    |
    |  1. Identify the caller
    |  2. Map them to a PrivX user (using configured source_type)
    |  3. Load that user's effective PrivX permissions
    |  4. Allow only tools whose required scopes they hold
    v
tools/list  →  filtered tool catalog
tools/call  →  allow or deny the specific tool
```

## Identifying the user

The MCP client presents an OAuth access token, or in `m2m` mode a configured service secret as a bearer. The server verifies it. For OAuth it reads identity claims such as email, UPN, or subject. For a service secret the PrivX username is the configured principal, and identity mapping is not applied.

That identity is then matched to a PrivX user directory entry, using the claim values against PrivX fields such as email, Windows account, or principal name. A value containing `@` matches the PrivX email and Windows account. Any other value matches the principal.

### Directory source (`source_type`)

The same person can exist more than once in PrivX, for example once in Active Directory and once via Microsoft Graph. The `[permissions]` key `source_type` selects which directory to use, with typical values `AD`, `LOCAL`, and `MICROSOFTGRAPH`.

- If several directory entries match the identifier, the server picks the one whose `source_type` matches the config.
- If none match, or more than one match with the same `source_type`, access that depends on PrivX permissions is denied.
- When no matching `source_type` is found but other directory entries match the identifier, the server logs those candidates to help with configuration mistakes.

See `permissions.source_type` in `privx-mcp-config-example.toml` and the resolution logic in `internal/mcp/runtime/permissions.go`.

### Why you cannot just pick any matching `source_type`

It may look as if setting `source_type` to whatever directory contains the user's identifier is enough. It is not.

Tool calls do not only look the user up for permission checks. They also open a PrivX session on behalf of that user through an External Token Provider configured in PrivX, and that connection is bound to **one specific user directory**. See [PrivX configuration](../server/privx.md#user-specific-client) for the exchange itself.

So two things must agree:

| Piece                                      | What it selects                                                                           |
| ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| MCP `permissions.source_type`              | Which PrivX user record to use when evaluating tool permissions                           |
| PrivX external connection's user directory | Which directory PrivX uses when accepting the user's external JWT and acting as that user |

If `source_type` points at a directory that is not the one tied to the external connection, permission resolution may find a user and look correct, while the actual PrivX session belongs to a different directory or fails to map the user at all. Matching `source_type` to _some_ directory that contains the username does not help if that directory is the wrong one for the connection.

In practice, choose the directory that the PrivX external connection is configured to use, then set `source_type` to that directory's type. Changing only the MCP config cannot retarget the PrivX-side connection.

### Caching

Resolved user and permission context is cached for `permissions.session_cache_ttl`, default 30 seconds, which avoids looking up PrivX for every tool in a list request or every rapid tool call. Set the TTL to `0` to disable caching.

When a tool call is denied because the **cached** roles lack a required scope, the server drops that entry, re-fetches roles from PrivX, and retries. Refresh is throttled by `permissions.refresh_cooldown`, default 1 minute, and `0` disables it. A deny that already came from a fresh PrivX lookup is not fetched again.

Revoking elevated permissions that are still in a valid cache waits for the TTL to expire, because a stale allow is not a deny and therefore never triggers the on-deny refresh.

### Role changes during an open session

After an on-deny refresh, the official MCP Go SDK cannot send `notifications/tools/list_changed` to the calling session alone. The tool result is JSON with `action: "restart_host_application"` and one of:

- `error: "roles_changed"` when the refreshed roles or permissions differ from the cache and the call is still denied.
- `error: "not_authorized"` when they do not differ, including cache-miss denials after the TTL expires.

The capability `tools.listChanged` is still advertised, for process-wide catalog changes such as tools added or removed on the shared server.

Whether the client catalog updates is client-specific:

- A later `tools/list` picks up the current role-scoped set, on reconnect, on a manual refresh, or when the client re-lists after a process-wide `tools.listChanged`.
- Clients that cache the catalog in the host application, as Cursor does, may keep the stale list even after an MCP reconnect or re-login. Fully quit and reopen the application. Restarting only the MCP server is not enough.

OAuth re-login is not required for role changes, because identity claims stay the same and roles come from PrivX. The call gate always uses the refreshed roles, so a tool that is no longer allowed is denied even when it remains visible.

## Which tools are registered

Before per-user checks run, the server decides which tools are available in this process (`internal/tools/register.go`). The filters run in a fixed order: `default_read_only`, then `whitelist`, then `blacklist`.

| Config                          | Effect                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `permissions.default_read_only` | When `true`, write-capable tools (`Writes: true`) are not registered.                                  |
| `permissions.whitelist`         | Only tool names with one of these left-to-right prefixes are registered. Empty means no prefix filter. |
| `permissions.blacklist`         | Tool names matching one of these prefixes are dropped after the whitelist. Empty means no deny filter. |

These are operator controls for the deployment, independent of any user's PrivX roles. Empty lists mean no filtering at that stage.

### Example

```toml
default_read_only = true
whitelist = ["role-", "connection-", "request-", "password-policy-", "whitelist-", "access-group-"]
```

1. `default_read_only` drops every `Writes: true` tool, which here removes the `*-create`, `*-update`, `*-delete`, `*-grant`, and `*-revoke` tools.
2. The whitelist keeps only tools whose names start with one of the prefixes.

The result is the read tools matching those prefixes. With `default_read_only = false` and the same whitelist, the matching write tools survive too. Adding `blacklist = ["access-group-delete"]` drops that one tool by name prefix while keeping the rest.

## What each tool requires

Each MCP tool is mapped to a required PrivX permission scope in `internal/tools/permissions.go`. Examples:

| Scope             | Example tools                                                          |
| ----------------- | ---------------------------------------------------------------------- |
| `hosts-view`      | `host-list`, `host-get`                                                |
| `hosts-manage`    | `host-create`, `host-update`, `host-delete` (also includes view tools) |
| `authenticated`   | Tools available to any signed-in user (`mcp-info`, `host-search`)      |
| _(none / public)_ | Tools with no permission requirement                                   |

The full tool-to-scope listing is in [MCP tools](../user/tools.md).

At startup that map is applied when tools are registered. The runtime then checks the caller's PrivX permissions against each tool's requirement.

Special cases:

- **No requirement**: always allowed, subject to the tool being registered.
- `authenticated`: allowed for any verified identity, and no PrivX role lookup is required for that tool.
- `privx-admin` **role**: users with this PrivX role bypass the specific permission checks.
- **Time-limited roles**: if a PrivX role has an active time or weekday window, its permissions only count while that window is open.

## Tool listing (`tools/list`)

When a client asks for the available tools, the server:

1. Reads the caller's identity from the request context.
2. Resolves that identity to PrivX permissions **once** for the whole list, not once per tool.
3. Keeps only tools the caller is allowed to use.

The result is a personalized catalog. Tools the user cannot invoke are omitted rather than shown and then rejected later.

Implementation: `internal/mcp/runtime/access.go` (`toolFilter` / `filterByPermissions`).

## Tool calls (`tools/call`)

When a client invokes a tool, the server runs a stricter path:

1. Require a verified identity, rejecting the call if it is missing.
2. Optionally enforce a per-identity rate limit (`request_window_seconds` / `max_requests_per_window`). A refused call stops here and does not log in to PrivX.
3. Authenticate and prepare the PrivX-facing user context for the call.
4. Look up the tool and check the same permission rules used for listing.
5. Allow the handler to run, or return an authorization error.

Each decision is logged with the tool name, identity claims, required scopes, and allow or deny outcome.

Implementation: `internal/mcp/runtime/access.go` (`authMiddleware`) and `internal/mcp/runtime/permissions.go` (`IsAllowed`).

Listing and calling share the identity mapping, the required scopes, and the effective PrivX permissions, including admin bypass and role time windows. The difference is operational: listing resolves the user once and filters many tools, while a call checks one tool and also runs authentication and optional rate limiting.

## Quick troubleshooting

| Symptom                                                              | Likely cause                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User sees almost no tools                                            | Identity did not map to a PrivX user, wrong `source_type`, or the user lacks the needed PrivX permissions.                                                                                                                                                                 |
| Log mentions non-matching `source_type` candidates                   | The identifier matched users in other directories. Set `permissions.source_type` to the directory used by the PrivX external connection, not just any directory that contains the user.                                                                                    |
| Permissions resolve, but PrivX actions fail or act as the wrong user | `source_type` does not match the user directory bound to the PrivX external connection.                                                                                                                                                                                    |
| Write tools never appear for anyone                                  | `default_read_only = true`, or the `whitelist` / `blacklist` prefixes exclude them.                                                                                                                                                                                        |
| Tool appears but call is denied                                      | The client may still show a stale catalog, see [Role changes during an open session](#role-changes-during-an-open-session). Also check rate limiting, a cooldown-skipped refresh, an expired session cache against a role window, or permissions that changed mid-session. |
| Everything works for `privx-admin` only                              | Expected when other users lack the specific PrivX scopes the tools require.                                                                                                                                                                                                |

## Related files

| Area                                  | Location                                                                                                 |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Tool to permission map                | `internal/tools/permissions.go`                                                                          |
| Registration and config filters       | `internal/tools/register.go`                                                                             |
| List vs call enforcement              | `internal/mcp/runtime/access.go`                                                                         |
| Identity resolution and PrivX checks  | `internal/mcp/runtime/permissions.go`                                                                    |
| End-user PrivX session (external JWT) | `internal/auth/privx`                                                                                    |
| Config keys                           | `[permissions]` in `privx-mcp-config-example.toml`, also [MCP server configuration](../server/SERVER.md) |
