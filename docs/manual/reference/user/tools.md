# MCP tools

Every tool the PrivX MCP server can register: 65 tools across 13 topics. The `echo` development tool is not covered.

## Related documents

- [User documentation](USER.md)
- [User-level security](../security/user_level_security.md)
- [Security considerations](../security/security.md)

Tool names, the Read/Write column, and the required permission scope are generated from code:

- Names and required scopes come from [`internal/tools/permissions.go`](../../../../internal/tools/permissions.go).
- The Read/Write column comes from each tool factory's `Writes` field in [`internal/tools/*/tool/`](../../../../internal/tools/).

`Read` tools survive `default_read_only = true`, while `Write` tools are pruned by it. See [User-level security](../security/user_level_security.md) for how registration-time filtering and per-call authorization interact.

Which tools a caller actually sees depends on their current PrivX roles. When those roles change during an open session, see [Role changes during an open session](../security/user_level_security.md#role-changes-during-an-open-session).

## Host tools

| Tool          | Description                                                                    | Type  | Permission      |
| ------------- | ------------------------------------------------------------------------------ | ----- | --------------- |
| `host-list`   | List PrivX hosts with pagination (created DESC).                               | Read  | `hosts-view`    |
| `host-get`    | Fetch a single PrivX host by id.                                               | Read  | `hosts-view`    |
| `host-search` | Search hosts by identity, endpoint, access, cloud, or state.                   | Read  | `authenticated` |
| `host-create` | Create a PrivX host with common_name, addresses, services, and principals.     | Write | `hosts-manage`  |
| `host-update` | Update an existing host by id. Only supplied fields are changed.               | Write | `hosts-manage`  |
| `host-delete` | Delete a host by id (refused if a connection from the last 24h is still open). | Write | `hosts-manage`  |

`host-search` is available to any signed-in user, but only returns hosts the caller already has access to unless they also hold `hosts-view`.

## Role tools

| Tool           | Description                                                             | Type  | Permission     |
| -------------- | ----------------------------------------------------------------------- | ----- | -------------- |
| `role-list`    | List all PrivX roles with pagination (created DESC).                    | Read  | `roles-view`   |
| `role-get`     | Get a single role by ID.                                                | Read  | `roles-view`   |
| `role-members` | Get users assigned to a role (created DESC).                            | Read  | `roles-view`   |
| `role-create`  | Create a new role (name required, permissions, comment, tags optional). | Write | `roles-manage` |
| `role-update`  | Full replacement update (fetch with role-get first).                    | Write | `roles-manage` |
| `role-delete`  | Delete a role by id (checks for members before deletion).               | Write | `roles-manage` |
| `role-grant`   | Grant a role to a user (permanent/floating/restricted).                 | Write | `roles-manage` |
| `role-revoke`  | Revoke a role from a user.                                              | Write | `roles-manage` |

### Role grant types

| Type              | Parameters                                | Description                                    |
| ----------------- | ----------------------------------------- | ---------------------------------------------- |
| `PERMANENT`       | (none)                                    | Role is always active                          |
| `FLOATING`        | `floating_length` (seconds)               | Role activates on use, expires after N seconds |
| `TIME_RESTRICTED` | `valid_from`, `valid_until` (RFC3339 UTC) | Role active only within time window            |

Time format examples: `"2025-01-15T09:00:00Z"`, `"2025-06-30T17:00:00+02:00"`.

### Role contextual restrictions

Roles can carry contextual restrictions (IP masks, time windows, weekdays) set via the `context` field in `role-create` and `role-update`:

- `enabled`: whether restrictions are active
- `block_role`: block (`true`) or alert (`false`) when conditions are not met
- `ip_masks`: allowed source IPs in CIDR notation
- `validity`: active weekdays (MON to SUN)
- `start_time` / `end_time`: daily time window
- `timezone`: IANA timezone

## User tools

| Tool                | Description                                                                                                   | Type  | Permission     |
| ------------------- | ------------------------------------------------------------------------------------------------------------- | ----- | -------------- |
| `user-list`         | List PrivX users (local and directory) with pagination.                                                       | Read  | `users-view`   |
| `user-get`          | Fetch a single PrivX user by id.                                                                              | Read  | `users-view`   |
| `user-search`       | Search users across local and directory sources.                                                              | Read  | `users-view`   |
| `user-get-roles`    | Fetch roles assigned to a user by user id.                                                                    | Read  | `users-view`   |
| `user-create-local` | Create a local user (username, full_name, email). Initial password is generated server-side and not returned. | Write | `users-manage` |
| `user-update-local` | Update an existing local user by id. Only supplied fields change.                                             | Write | `users-manage` |
| `user-delete-local` | Delete a local user by id (fetch with user-get first).                                                        | Write | `users-manage` |

`user-create-local`, `user-update-local`, and `user-delete-local` operate on the PrivX Local User Store only. Directory users cannot be modified or removed here.

## Access request tools

| Tool                   | Description                                                                                                                           | Type  | Permission           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------- |
| `request-list`         | List access requests with pagination (created DESC). `filter` is `ALL`, `ACTIVE_APPROVALS`, `APPROVALS`, or `REQUESTS`.               | Read  | `workflows-requests` |
| `request-search`       | Search access requests (keywords/start_time/end_time in `search`, `filter` is top-level).                                             | Read  | `workflows-requests` |
| `request-get`          | Fetch a single access request by id (raw record).                                                                                     | Read  | `workflows-requests` |
| `request-set-decision` | Approve or deny a WAITING access request.                                                                                             | Read  | `workflows-requests` |
| `request-create`       | Create a GRANT access request (FLOATING/TIME_RESTRICTED). The authenticated user is the requester. `target_user` may be someone else. | Write | `workflows-requests` |
| `request-delete`       | Delete/withdraw a pending request by id.                                                                                              | Write | `workflows-requests` |
| `request-revoke-role`  | Revoke the target role granted by an approved request.                                                                                | Write | `workflows-requests` |

### Why `request-set-decision` is classified as Read

`request-set-decision` calls a mutating PrivX API, but is marked `Writes: false`. The flag does not describe whether the underlying API mutates state. It controls whether the tool survives read-only registration mode (`default_read_only = true`, which prunes all `Writes: true` tools).

Approving or denying creates, modifies, or destroys nothing. It advances a request that is already `WAITING` along the approval steps its workflow already defines. Approval is also a day-to-day operator action, so flagging it as a write would let a common hardening default silently break the approval workflow for deployments that are meant to be non-provisioning rather than idle.

Access is still gated per call: the caller must hold the approver role required by the request step, enforced in `preflightDecision`, and the tool still requires the `workflows-requests` permission. Classifying it as Read relaxes only the read-only-mode pruning. See [Permissions and trust](../security/security.md#permissions-and-trust).

## Connection tools

| Tool                   | Description                                               | Type  | Permission              |
| ---------------------- | --------------------------------------------------------- | ----- | ----------------------- |
| `connection-list`      | List connections with pagination (connected DESC).        | Read  | `connections-view`      |
| `connection-get`       | Get a single connection by ID.                            | Read  | `connections-view`      |
| `connection-search`    | Search by status, type, user, host, time range, keywords. | Read  | `connections-view`      |
| `connection-terminate` | Forcefully end an active session (status CONNECTED).      | Write | `connections-terminate` |

### Compact view vs raw

By default, connection tools return a compact 17-field projection per connection (user, target, status, timing, traffic). Pass `raw=true` to get the full unfiltered API response including nested `user_data`, `target_host_data`, `target_network_data`, `target_api_data`, and `trail` objects.

Compact fields: `id`, `type`, `mode`, `status`, `user`, `target_host`, `target_host_address`, `target_host_account`, `authentication_method`, `target_host_roles`, `remote_address`, `connected`, `disconnected`, `duration`, `bytes_in`, `bytes_out`, `audit_enabled`.

### Connection search filters

- `status`: CONNECTED, DISCONNECTED, TERMINATED
- `type`: SSH, RDP, VNC, WEB, DB, NET, API
- `keywords`: free-text search
- `target_host_common_name`: filter by host name
- `connected_start` / `connected_end`: RFC3339 time range

## Network target tools

| Tool                    | Description                                                                              | Type  | Permission               |
| ----------------------- | ---------------------------------------------------------------------------------------- | ----- | ------------------------ |
| `network-target-list`   | List network targets with pagination (created DESC).                                     | Read  | `network-targets-view`   |
| `network-target-get`    | Fetch a single network target by id.                                                     | Read  | `network-targets-view`   |
| `network-target-search` | Search network targets by keywords, tags, or filter expression.                          | Read  | `network-targets-view`   |
| `network-target-create` | Create a network target (name required, destinations need at least `selector.ip.start`). | Write | `network-targets-manage` |
| `network-target-update` | Update an existing network target by id. Only supplied fields change.                    | Write | `network-targets-manage` |
| `network-target-delete` | Delete a network target by id (fetch with network-target-get first).                     | Write | `network-targets-manage` |

## API target tools

| Tool                | Description                                                            | Type  | Permission           |
| ------------------- | ---------------------------------------------------------------------- | ----- | -------------------- |
| `api-target-list`   | List PrivX API targets with pagination (created DESC).                 | Read  | `api-targets-view`   |
| `api-target-get`    | Fetch a single API target by id (sensitive credential fields omitted). | Read  | `api-targets-view`   |
| `api-target-delete` | Delete an API target by id (fetch with api-target-get first).          | Write | `api-targets-manage` |

`api-target-*` has view and manage scopes, but the only write tool is `api-target-delete`. There is no create or update tool.

## Access group tools

| Tool                  | Description                                                  | Type  | Permission             |
| --------------------- | ------------------------------------------------------------ | ----- | ---------------------- |
| `access-group-list`   | List all access groups.                                      | Read  | `access-groups-manage` |
| `access-group-get`    | Get a single access group by ID.                             | Read  | `access-groups-manage` |
| `access-group-create` | Create an access group (name required).                      | Write | `access-groups-manage` |
| `access-group-update` | Full replacement update (fetch with access-group-get first). | Write | `access-groups-manage` |
| `access-group-delete` | Delete an access group by ID.                                | Write | `access-groups-manage` |

Access groups partition the PrivX environment into security domains. Each group has its own certificate authority (CA) for issuing ephemeral certificates. The default access group cannot be deleted. Deleting a non-default group may orphan hosts, roles, and targets assigned to it.

## Password policy tools (admin only)

| Tool                     | Description                                     | Type  | Permission    |
| ------------------------ | ----------------------------------------------- | ----- | ------------- |
| `password-policy-list`   | List all password rotation policies.            | Read  | `privx-admin` |
| `password-policy-get`    | Get a single policy by ID.                      | Read  | `privx-admin` |
| `password-policy-create` | Create a policy (name + max_versions required). | Write | `privx-admin` |
| `password-policy-update` | Full replacement update (fetch first).          | Write | `privx-admin` |
| `password-policy-delete` | Delete a policy by ID.                          | Write | `privx-admin` |

Duration fields use ISO 8601 format: `P30D` (30 days), `PT1H` (1 hour), `PT5M` (5 minutes).

## SSH command whitelist tools (admin only)

| Tool                 | Description                                               | Type  | Permission    |
| -------------------- | --------------------------------------------------------- | ----- | ------------- |
| `whitelist-list`     | List all SSH command whitelists with pagination.          | Read  | `privx-admin` |
| `whitelist-get`      | Get a single whitelist by ID.                             | Read  | `privx-admin` |
| `whitelist-search`   | Search whitelists by keywords (name/comment).             | Read  | `privx-admin` |
| `whitelist-create`   | Create a whitelist (name, type, patterns required).       | Write | `privx-admin` |
| `whitelist-update`   | Full replacement update (fetch with whitelist-get first). | Write | `privx-admin` |
| `whitelist-delete`   | Delete a whitelist by ID.                                 | Write | `privx-admin` |
| `whitelist-evaluate` | Dry-run test commands against whitelist patterns.         | Read  | `privx-admin` |

### Whitelist pattern types

| Type    | Syntax                       | Example                              |
| ------- | ---------------------------- | ------------------------------------ |
| `glob`  | Shell wildcards (`*`, `?`)   | `tail /var/log/m*`                   |
| `regex` | Go RE2 (must start with `^`) | `^systemctl\s+(status\|show)\s+\w+$` |

### Whitelist evaluate

`whitelist-evaluate` tests commands against a whitelist's patterns without executing anything. Useful for validating patterns before deploying to hosts. Supports `rshell_variant`: `bash` (default) or `posix`.

## Audit event tools

| Tool                 | Description                                                                                                                               | Type | Permission  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---- | ----------- |
| `audit-event-codes`  | List PrivX audit event codes with names and descriptions. Use to look up `event_id` / `event_name` when interpreting list/search results. | Read | `logs-view` |
| `audit-event-list`   | List audit events with pagination (created DESC).                                                                                         | Read | `logs-view` |
| `audit-event-search` | Search audit events by keywords, user, host, connection, session, or time window.                                                         | Read | `logs-view` |

## Status tools

| Tool                     | Description                                                                   | Type | Permission  |
| ------------------------ | ----------------------------------------------------------------------------- | ---- | ----------- |
| `status-components`      | Get PrivX component status for all hosts, or one host when `hostname` is set. | Read | `logs-view` |
| `status-instance`        | Get PrivX instance status from monitor-service.                               | Read | `logs-view` |
| `status-monitor-service` | Get monitor-service microservice status.                                      | Read | `logs-view` |

`audit-event-*` and `status-*` share the `logs-view` scope.

## Info tool

| Tool       | Description                                                                                                                                             | Type | Permission      | Trusted |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | --------------- | ------- |
| `mcp-info` | Return MCP/PrivX information for the current session: authenticated caller info, PrivX instance config, optional context topics, and example resources. | Read | `authenticated` | Yes     |

`mcp-info` is the one `Trusted` tool: it bypasses the runtime security envelope (stripping, word lists, and the `{meta, data}` wrapper) because its payload is server-generated documentation and example JSON. The handler still sanitizes the PrivX-sourced strings it embeds (caller name, role names) itself. See [Trusted tools](../security/security.md#trusted-tools).
