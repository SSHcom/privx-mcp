# User documentation

## Related documents

- [MCP tools](tools.md)
- [User-level security](../security/user_level_security.md)

## Which tools you can see and use

You only see tools you are allowed to call, because visibility and usage follow the same PrivX permissions from your roles. Read tools are guarded by a `view` permission and write tools by a `manage` permission.

| Resource            | Permissions                                                       |
| ------------------- | ----------------------------------------------------------------- |
| Hosts               | `hosts-view`, `hosts-manage`                                      |
| Users               | `users-view`, `users-manage`                                      |
| Roles               | `roles-view`, `roles-manage`                                      |
| Network targets     | `network-targets-view`, `network-targets-manage`                  |
| API targets         | `api-targets-view`, `api-targets-manage`                          |
| Connections         | `connections-view`, `connections-manage`, `connections-terminate` |
| Access requests     | `workflows-requests`                                              |
| Audit logs & Status | `logs-view`                                                       |
| Access groups       | `access-groups-manage`                                            |

A few tools, such as `mcp-info` and `host-search`, are available to any signed-in user. `host-search` only returns hosts you already have access to unless you also hold `hosts-view`. Users with the `privx-admin` role can use all tools.

[MCP tools](tools.md) lists every registered tool with its Read/Write classification, required permission scope, and per-topic notes.

If you need a tool that is not visible, request a PrivX role that includes the required permission in the PrivX UI, or ask an administrator.

## Prompt guide

Some notes about effectively directing your AI client to use the MCP server.

TBD....
