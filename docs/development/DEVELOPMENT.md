# Development

How to build, test, lint and run the MCP server as a developer.

## Table of contents

- [Project structure](#project-structure)
- [Tasks](#tasks)
- [Building](#building)
- [Running the server](#running-the-server)
- [Secure code](#secure-code)
- [AI directions](#ai-directions)

## Project structure

```
cmd/privx-mcp-server/  # Server binary entry point
cmd/privx-mcp-proxy/   # Stdio proxy entry point
internal/
  auth/                # Auth pipeline (verify -> map -> mint -> exchange)
    oauth/             # OIDC token verification and discovery
      wellknown/       # RFC 9728 metadata, OAuth AS proxy, DCR stub
    privx/             # PrivX JWT minting and token exchange
  bootstrap/           # Runtime assembly and HTTP server construction
  config/              # TOML + env config loading and validation
  mcp/
    registry/          # Tool registry interface and implementation
    runtime/           # Transport-agnostic MCP runtime
    transport/         # HTTP edge routes and bearer challenge middleware
  proxy/               # Stdio proxy library (see stdio-proxy.md)
  service/
    http/              # Shared HTTP mux + server helpers
    logging/           # Logging
    privx_api/         # Thin PrivX API wrappers (users, roles)
    security/          # MCP boundary hardening (sanitize, blacklist, envelope)
    session/           # Per-identity user-context cache and rate limiting
  testutil/testconn/   # Test-only fake Connector and auth-context helpers
  tools/
    common/            # Shared tool constants and paging/sort helpers
    info/              # mcp-info tool (session/instance/context/resource info)
    <topic>/tool/      # One directory per topic: hosts, users, requests, connections, ...
    permissions.go     # Single source of truth for tool -> required permission scope
    register.go        # Topic registration + registration-time filtering
  utils/               # Shared helpers (email, file, string, bool, map readers, date)
```

## Tasks

Routine jobs run through [Task](https://taskfile.dev/), which must be installed. Run `task` (in project root) to list all tasks.

| Task            | `task` command     | Under the hood                                                             |
| --------------- | ------------------ | -------------------------------------------------------------------------- |
| Build server    | `task build`       | `go build -o bin/privx-mcp-server ./cmd/privx-mcp-server`                  |
| Build proxy     | `task build:proxy` | `go build -o bin/privx-mcp-proxy ./cmd/privx-mcp-proxy`                    |
| Image (glibc)   | `task image:glibc` | `docker build -f deploy/docker/Dockerfile.glibc -t privx-mcp-server:dev .` |
| Image (musl)    | `task image:musl`  | `docker build -f deploy/docker/Dockerfile.musl -t privx-mcp-server:dev .`  |
| Test            | `task test`        | `go test ./...`                                                            |
| Race detector   | `task race`        | `go test -race ./...`                                                      |
| Lint            | `task lint`        | `golangci-lint run ./...`                                                  |
| Format          | `task format`      | `gofmt -w ./internal ./cmd/privx-mcp-server ./cmd/privx-mcp-proxy`         |
| Fetch/tidy deps | `task dep`         | `go get ./... && go mod tidy && go mod vendor`                             |

The stdio proxy is covered in [stdio-proxy.md](stdio-proxy.md).

## Building

- Binaries are written to `bin/`.
- The Go toolchain is pinned via `GOTOOLCHAIN` in `Taskfile.yml`.

Cross-platform server builds, each writing `bin/privx-mcp-server-<target>`:

| Task                          | CGO | Notes                                       |
| ----------------------------- | --- | ------------------------------------------- |
| `task build:linux:amd64`      | on  |                                             |
| `task build:linux:arm64`      | on  | Needs an ARM64 cross C compiler (see below) |
| `task build:linux:amd64-musl` | off | Static; runs on musl systems such as Alpine |
| `task build:linux:arm64-musl` | off | Static; no ARM64 C toolchain needed         |
| `task build:darwin:amd64`     | on  |                                             |
| `task build:darwin:arm64`     | on  |                                             |
| `task build:windows:amd64`    | on  | Output has `.exe` suffix                    |

`build:linux:arm64` uses `aarch64-linux-gnu-gcc` by default (override with `CC_ARM64`). Build it on Linux, natively or in a Linux container. Required packages:

- Debian/Ubuntu: `gcc-aarch64-linux-gnu libc6-dev-arm64-cross`
- Arch Linux: `aarch64-linux-gnu-gcc aarch64-linux-gnu-glibc`

## Running the server

The server loads the first config file it finds, in this order:

1. `$PRIVX_MCP_CONFIG`
2. `--config <path>`
3. `/etc/privx-mcp/config.toml`
4. `./privx-mcp-config.toml`

The simplest way to get started is to copy `privx-mcp-config-example.toml` to `privx-mcp-config.toml` and modify it as needed:

- Configuration options are in [MCP server configuration](../manual/reference/server/SERVER.md)
- After creating the configuration run `./bin/privx-mcp-server` from project root

Pick a setup:

- **m2m**: simplest when you are not working on OAuth. See [Configure machine-to-machine access](../manual/04-m2m.md).
- **OAuth, local server**
  - Run Keycloak with `docker compose -f docker-compose-keycloak.yml up`
  - Create a client configuration in Keycloak. The [Keycloak OIDC](../../deploy/docker/demo/README.md) documentation has details about this.
  - run `bin/privx-mcp-server`
- **Full end-to-end**: Read [Docker demo](../../deploy/docker/demo/README.md) on how to run a Docker-only setup. Note that hot-reloading is not supported, so use one of the above as your "daily driver".

## Secure code

- [security-decisions.md](security-decisions.md): product behaviour we inspected and chose not to change.
- [security-scan.md](security-scan.md): how to run a security review (ask your AI to run this).

## AI directions

- [AGENTS.md](../../AGENTS.md) is the guide AI coding agents follow in this repository. It also helps people adding or changing MCP tools:
  - how tools are grouped by PrivX resource (a "topic" such as hosts or users) and laid out under `internal/tools/`
  - how a tool handler parses input, calls PrivX and formats its result
  - which files to edit so a new tool is registered and gets its permissions
- Security reviews follow [security-scan.md](security-scan.md):
  - Record results with `python3 scripts/security-scan-report.py` (`add` for issues, `ok` for passed checks).
  - Run `markdown` to write `README.md`, `issues.md` and `passed.md` in the run directory.
