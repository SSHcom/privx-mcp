# Run PrivX MCP Server with systemd (user service)

This guide describes how to install `privx-mcp-server` as a user-level `systemd` service. It runs under a user account without root privileges, starts automatically, restarts on failure, and logs to the user journal.

## 1) Build the binary

From the repository root:

```bash
task build
```

That produces `bin/privx-mcp-server`.

If you are cross-building, use one of:

```bash
task build:linux:amd64|amd64-musl
task build:linux:arm64|arm64-musl
task build:darwin:amd64
task build:darwin:arm64
task build:windows:amd64
```

## 2) Move the binary to the target host and install files

Pick the artifact that matches the target host.

- Local host build: `bin/privx-mcp-server`
- Linux amd64: `bin/privx-mcp-server-linux-amd64`
- Linux arm64: `bin/privx-mcp-server-linux-arm64`
- Linux amd64 musl: `bin/privx-mcp-server-linux-amd64-musl`
- `etc`

Take that artifact from your build environment and place it on the target host where the service will run. The target host may be the same machine where you built it, or a different machine.

Then run the following commands on the target host:

```bash
mkdir -p "$HOME/.privx-mcp"

# linux-amd64 example
cp /path/to/privx-mcp-server-linux-amd64 "$HOME/.privx-mcp/privx-mcp-server-linux-amd64"

chmod 700 "$HOME/.privx-mcp/privx-mcp-server-linux-amd64"

chmod 600 "$HOME/.privx-mcp/privx-mcp-config.toml"
```

Create and edit the configuration file:

```bash
$EDITOR "$HOME/.privx-mcp/privx-mcp-config.toml"
```

Configuration reference: [MCP server configuration](../../docs/manual/reference/server/SERVER.md).

Leave `log_file` unset (the default) so the server logs to stdout. *systemd* captures that in the user journal. If `log_file` is set, logs go to that file instead and will not appear as journal/syslog entries.

## 3) Create the user service unit

Create `~/.config/systemd/user/privx-mcp-server.service`:

```bash
mkdir -p "$HOME/.config/systemd/user"
$EDITOR "$HOME/.config/systemd/user/privx-mcp-server.service"
```

With the following content:

```ini
[Unit]
Description=PrivX MCP Server

[Service]
Type=simple
WorkingDirectory=%h/.privx-mcp
ExecStart=%h/.privx-mcp/privx-mcp-server-linux-amd64 --config %h/.privx-mcp/privx-mcp-config.toml
SyslogIdentifier=privx-mcp-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

If you copied another binary in step 2 (for example `...-linux-arm64` or `...-musl`), change the binary name in `ExecStart` to match.


| Option             | Value                  | Meaning                                                                                             |
| ------------------ | ---------------------- | --------------------------------------------------------------------------------------------------- |
| `Description`      | `PrivX MCP Server`     | Name shown by `systemctl status` and in the journal.                                                |
| `Type`             | `simple`               | The server runs in the foreground; systemd treats it as started as soon as the process is launched. |
| `WorkingDirectory` | `%h/.privx-mcp`        | Directory the server runs in. `%h` expands to your home directory.                                  |
| `ExecStart`        | binary `--config` file | Command that starts the server with the config file from step 2.                                    |
| `SyslogIdentifier` | `privx-mcp-server`     | Tag on journal lines, so logs are easy to filter.                                                   |
| `Restart`          | `on-failure`           | Restart the server if it exits with an error or crashes, but not after a clean stop.                |
| `RestartSec`       | `5`                    | Wait 5 seconds before restarting.                                                                   |
| `WantedBy`         | `default.target`       | Start the service with your user session once it is enabled.                                        |


The unit does not wait for the network. A user service cannot depend on system units such as `network-online.target`, so the server may start before the network is up, especially at boot with lingering enabled (see step 4). If the server then fails to start, for example because it cannot fetch the OIDC discovery document, `Restart=on-failure` retries every 5 seconds until the network is available. If you need a hard guarantee that the network is up first, install the unit as a system service in `/etc/systemd/system` with `User=` set and `After=network-online.target` and `Wants=network-online.target` added under `[Unit]`; this requires root.

## 4) Enable and start the service

```bash
systemctl --user daemon-reload
systemctl --user enable --now privx-mcp-server.service
```

A user service starts when you log in and stops when your last session ends. To keep it running without an active login, and to start it at boot, enable lingering for your account:

```bash
sudo loginctl enable-linger "$USER"
```



## 5) Verify and troubleshoot

```bash
systemctl --user status privx-mcp-server.service
journalctl --user -u privx-mcp-server.service -f
```

Journal lines are tagged `privx-mcp-server`. They only appear when `log_file` is unset.