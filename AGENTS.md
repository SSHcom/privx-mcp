# AGENTS

## Internal Package Overview

`internal/` is organized by responsibility:

- `auth/`: authentication flows and identity integrations (`oauth`, `privx`, `m2m` service secrets, context, and auth errors).
- `bootstrap/`: server startup wiring.
- `config/`: config models, loading, defaults, overrides, and validation.
- `mcp/`: MCP runtime (`runtime`), HTTP transport (`transport`), and tool registry (`registry`).
- `proxy/`: local MCP proxy that forwards tool calls to a remote session (`bridge`, `oauth`, `remote`, `store`, `config`, `httpx`, `help`).
- `service/http/`: HTTP server and mux composition for exposed endpoints.
- `service/logging/`: slog wrapper with optional lumberjack file rotation.
- `service/privx_api/`: thin PrivX API wrappers (users, roles, workflow requestable roles) used by runtime and tools.
- `service/security/`: MCP boundary hardening (sanitizing, response word filter, response envelope). See `docs/manual/reference/security/security.md`.
- `service/session/`: per-identity user-context cache and tool-call rate limiting.
- `testutil/testconn/`: test-only fake `restapi.Connector` and auth-context helpers for tool handler tests.
- `tools/`: tool registration (`register.go`, `permissions.go`) and one package per topic. Handlers live in `tool/` unless noted.
  - `tools/common/`: shared tool defaults and paging/sort helpers.
  - `tools/access_groups/`: access groups; handlers only.
  - `tools/api_targets/`: API-target field selection.
  - `tools/audit_events/`: audit events; handlers only.
  - `tools/connections/`: connection field selection.
  - `tools/echo/`: package `devtools`; testing-only `echo` tool via `TestTools()` (no `tool/` subpackage).
  - `tools/hosts/`: host schemas, converters, field selection, and edits.
  - `tools/info/`: `mcp-info` (session, instance, context, example resources). `All(snapshot)` lives in this package (no `tool/` subpackage).
  - `tools/network_targets/`: network-target schemas, converters, field selection, and edits.
  - `tools/password_policies/`: password-policy fields.
  - `tools/requests/`: access-request field selection.
  - `tools/roles/`: roles (including members, grant, and revoke); handlers only.
  - `tools/status/`: status field selection.
  - `tools/target_domains/`: target-domain fields and input schema.
  - `tools/users/`: user schemas, field selection, and edits.
  - `tools/user_secrets/`: personal and global vault secrets; handlers only.
  - `tools/whitelists/`: SSH command whitelists; handlers only.
- `utils/`: shared helpers (strings, files, map readers, JSON, dates).
- `version/`: build identity from the embedded `version.json` (server and proxy).

## Anatomy of a Tool Topic

A topic is one resource family (e.g. `hosts`, `users`, `network_targets`). Tools are named `{resource}-{action}` (hyphenated, lowercase): `host-list`, `user-search`, `network-target-get`.

### Package layout

```
internal/tools/<topic>/
  response_field_helpers.go   # default fields, Select*/Format*, redaction
  …                           # patch helpers, schemas as needed
  tool/                       # MCP definitions + handlers only
    all.go                    # All() → []registry.Tool
    list.go / search.go / get.go / …
```

- Parent package (`users`, `hosts`, …): shared logic used by handlers and tests; no `registry.Tool` factories. Topics with no shared helpers keep handlers only under `tool/`.
- `tool/` subpackage: one file per tool; each exports a factory (`List()`, `Search()`, …) returning `registry.Tool` (`Name`, `Description`, `Writes`, `InputSchema`, `Handler`).
- `All()` aggregates the topic’s tools for registration. `info.All` takes an instance snapshot. `echo` (package `devtools`) exposes `TestTools()` instead.

### How it is glued together

```
bootstrap → registry.NewRegistry()
         → tools.Register(reg, cfg)
              → <topic>/tool.All()
              → filterTools (sensitive gate / default_read_only / whitelist / blacklist)
              → applyPermissions (from permissions.go)
              → reg.Register(...)
         → runtime registers each tool on the MCP server
```

When adding a topic, wire these places:

1. `internal/tools/<topic>/tool/` — factories + handlers; `All()`.
2. `internal/tools/register.go` — `reg.Register(applyPermissions(filterTools(<topic>tools.All(), permissions))...)`.
3. `internal/tools/permissions.go` — view/manage scopes and tool name lists (single source of `RequiredPermissions`).
4. `internal/tools/common/limits.go` — default page size for list/search if paginated; use `common.ParsePaging` / sort schema helpers for `sortKey`/`sortDir`.
5. Tests: `tool/all_test.go` (names + `Writes`); extend `permissions_test.go` for the new scopes.

### Tool Handler Conventions

Tool handlers take `(ctx, params map[string]any) (*registry.ToolResult, error)`:

1. `auth.FromContext(ctx)` → require `Connector`.
2. Parse/validate params via `utils.*FromMap` (return `registry.ErrorResult`, not a Go error, for validation/API failures). For paginated list/search, use `common.ParsePaging` and pass `paging.FilterOptions()` (always sorts; default `created` DESC).
3. Call the PrivX SDK client built from `authCtx.Connector` (e.g. `hoststore.New`, `networkaccessmanager.New`). Prefer the SDK directly; use `service/privx_api` only for shared cross-topic helpers.
4. Project with topic `Format*` helpers (`fields` / nested `*Fields` CSV + `raw`); append `common.PresentationGuidance` to descriptions.
5. List/search return a pagination envelope: `items`, `count`, `limit`, `offset`, `returned`, `remaining`, `pagesRemaining` (search may add `nextOffset`).
6. `Writes: true` only for mutating tools; read-only mode drops those at registration.
7. Return the plain payload JSON. The runtime sanitizes string values, replaces configured whole words from `[permissions].response_filter` (empty means no replacement), and wraps success results in the `service/security` `{meta, data}` envelope; handlers must not build the envelope themselves. List rows and pagination stay; a match is replaced in that string. Tools named `whitelist-*` and tools flagged `Sensitive` are sanitized and wrapped but not word-filtered. Create and update tools (names containing `-create` or `-update`, including `user-create-local` and `user-update-local`) are rejected before the handler runs when any parameter value contains `[redacted]`, including tools that skip word replacement. Error results (`registry.ErrorResult`) are delivered unwrapped. `Trusted: true` opts a tool out of all of it (server-generated content only, e.g. `mcp-info`); `mcp-info` still runs PrivX-sourced names through `security.PrepareStrings` with the filter from context. `target-domain-managed-account-checkout` returns PrivX strings unchanged.

Reference topics: `users` (list/search/get + nested role fields), `hosts` (nested service/principal fields).

## Security review

When asked to security-scan this repository, follow [docs/development/security-scan.md](docs/development/security-scan.md). Record findings in the JSON store with `scripts/security-scan-report.py`; regenerate README.md, issues.md, and passed.md with `markdown`. Do not keep the report only in chat. Accepted product behaviour is in [docs/development/security-decisions.md](docs/development/security-decisions.md).

## Project Compatibility Policy

Do not preserve legacy behavior for historical compatibility. Do not add backward-compatibility aliases, shims, or migration layers unless explicitly requested by the user.

Prefer clean, direct implementations and strict configuration/schema validation over compatibility accommodations.

### Documentation and comment language

- Do not use the word "canonical" - it seems to be prevalent among LLMs, but is not often used by people.
- Do not wrap markdown paragraphs with newlines. A paragraph must be one continuous line regardless of editor-defined max line length. Hard-wrapped lines can render poorly depending on the markdown viewer.
