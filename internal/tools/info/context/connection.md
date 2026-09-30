# Connections

Users can connect to target host accounts based on their role assignments. A host can have multiple target accounts, and account-to-role mappings guard who can use each account.

## Connection links

Use `privx.privx_base_url` from the `mcp-info` response as the base URL.
The user must already be logged into that PrivX instance in their default browser for these links to open a working session.

Before creating a link, look up the host with `host-search` or `host-get`:

- Pick the account username from `host.principals[].principal` (for SSH/RDP links).
- Pick the target endpoint from `host.services[]` for the intended service.
  - SSH and RDP usually use `service.address` as the target host/IP.
  - Web uses the full `service.address` value (often prefixed like `web/https://...`).
- For Web links, also include `host.id` as `targetId`.

Link patterns:

- SSH: `{privx_base_url}/privx/connections/ssh?account={principal}&target={service.address}`
- RDP: `{privx_base_url}/privx/connections/rdp?account={principal}&target={service.address}`
- VNC: `{privx_base_url}/privx/connections/vnc?account={principal}&target={service.address}`
- WEB: `{privx_base_url}/privx/connections/web?target={urlencoded(service.address)}&targetId={host.id}`

***
Related resource examples: `host`, `connection`.
