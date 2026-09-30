# Stdio proxy development

The proxy is a CLI MCP **client** of the that provides stdio access to agents.

## Package structure

| Path                     | Responsibility                                        |
| ------------------------ | ----------------------------------------------------- |
| `cmd/privx-mcp-proxy/`   | CLI, config path, process exit                        |
| `internal/proxy/config/` | Load/validate the single TOML file                    |
| `internal/proxy/oauth/`  | Discovery, PKCE, callback, tokens, in-process refresh |
| `internal/proxy/httpx/`  | HTTP client: timeouts, allow-http                     |
| `internal/proxy/remote/` | Streamable HTTP client wiring (Go MCP SDK)            |
| `internal/proxy/bridge/` | Stdio ↔ remote tool forwarding                        |
| `internal/proxy/store/`  | On-disk tokens, keyed by server identity              |

## Build and run

```bash
task build:proxy
./bin/privx-mcp-proxy my-config-file.toml            # stdio MCP server for the host
./bin/privx-mcp-proxy --connect my-config-file.toml  # list remote tools and exit
./bin/privx-mcp-proxy --help                         # See all CLI options
./bin/privx-mcp-proxy --version                      # See the version (not synced with PrivX)
```

- Start by copying `privx-mcp-proxy-example.toml` and modify as needed.
- Read more about configuration and how to run from the [privx-mcp-proxy](../manual/reference/clients/privx-mcp-proxy.md) reference document.

## Tests

- `go test` uses `httptest` only.
- Unit tests must not call live PrivX or Keycloak.

## Features

Config:

- One TOML file: `mcp_url`, `allow_http`, `log_level` / `log_file`, `[callback]`, static `[client]`.

Auth:

- Discovery via RFC 9728 protected-resource metadata and authorization-server metadata; unauthenticated `/mcp` is supported.
- Static confidential client with authorization code + PKCE.
- Client auth: `client_secret_post` or `client_secret_basic`.
- Loopback callback: `localhost` in `redirect_uri`, bound to `127.0.0.1`.
- Silent access-token refresh while stdio is up: proactive skew plus one retry on 401.
- `invalid_grant` deletes the token file; the host must restart the proxy to log in again.

Token storage:

- Files under `~/.mcp-auth/privx-mcp-proxy-v1`, overridable with `$PRIVX_MCP_PROXY_AUTH_DIR`.
- Does not read mcp-remote's files.
- `--reset-session` does not read, write or delete the file for that process and sends `prompt=login`; tokens live in memory until stdio closes.

Transport:

- Streamable HTTP only (`DisableStandaloneSSE`).
- Works with sessioned (`Mcp-Session-Id`) and stateless `/mcp`.
- On remote session 404 (`mcp.ErrSessionMissing`): reopen the session and retry that `tools/call` once. Concurrent calls share one reopen. The local `tools/list` is not rebuilt.

`--connect` diagnostics:

- Logs request/response headers during discovery, MCP connect and list, with sensitive headers redacted.
- Prints the inferred mode (`stateless`, `sessioned` or `unknown`) based on `Mcp-Session-Id`.

## Not implemented

Not a roadmap. For these, use mcp-remote or a host with native HTTP and DCR.

- **DCR** (dynamic client registration), including the server's `/register` stub. `client_id` is required; there is no public-client default.
- Mid-session browser reauthorization. A dead refresh token means restarting the proxy from the host.
- SSE transport.
