# AGENTS

## Internal Package Overview

`internal/` is organized by responsibility:

- `auth/`: authentication flows and identity integrations (`oauth`, `privx`, context, and auth errors).
- `bootstrap/`: server startup wiring.
- `config/`: config models, loading, defaults, overrides, and validation.
- `mcp/`: MCP runtime (`runtime`), HTTP transport (`transport`), and tool registry (`registry`).
- `service/http/`: HTTP server and mux composition for exposed endpoints.
- `service/privx_api/`: thin PrivX API wrappers (users, roles) used by runtime and tools.
- `service/security/`: MCP boundary hardening applied by the runtime — `Sanitize` (drops invisible/control runes), `FindBlacklisted` (partial + full-word term lists), `DefaultOverrides` (key-scoped allowed terms such as `root` on `principal`/`name`, and the command/action terms on `whitelist_patterns` for the SSH command whitelist tools — injection terms stay blocked there), `Prepare` (one in-place walk of string values combining both), `PrepareOutput` (same walk for tool results: drops failing rows from a top-level `items` array instead of rejecting the page), and `Wrap` (the `{meta, data}` response envelope). Tools flagged `Trusted` are exempt; see `docs/manual/reference/security/security.md`.
- `service/session/`: per-identity user-context cache and tool-call rate limiting.
- `testutil/testconn/`: test-only fake `restapi.Connector` (route-based dispatch + JSON round-trip) and auth-context helpers for exercising MCP tool handlers without a live PrivX server. Imported only from `*_test.go` files.
- `tools/`: tool registration and topic implementations (`hosts`, `users`, `requests`, `network_targets`, `devtools`).
  - `tools/common/`: shared tool defaults (e.g. list/search page sizes) and paging/sort helpers (`ParsePaging`, `SortKeySchema`, `SortDirSchema`; default sort `created` DESC).
  - `tools/hosts/`: shared host schemas, converters, field selection, and edits.
  - `tools/hosts/tool/`: MCP host tool definitions and handlers only.
  - `tools/users/`: shared user field selection and response helpers.
  - `tools/users/tool/`: MCP user tool definitions and handlers only.
  - `tools/requests/`: shared access-request field selection and response helpers.
  - `tools/requests/tool/`: MCP access-request tool definitions and handlers only.
  - `tools/network_targets/`: shared network-target field selection and response helpers.
  - `tools/network_targets/tool/`: MCP network-target tool definitions and handlers only.
- `utils/`: shared helpers (`email`, file, string, bool, map readers like `StringFromMap`, JSON `ToJSONMap`); timezone/weekday logic lives in `utils/date`.

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

- Parent package (`users`, `hosts`, …): shared logic used by handlers and tests; no `registry.Tool` factories.
- `tool/` subpackage: one file per tool; each exports a factory (`List()`, `Search()`, …) returning `registry.Tool` (`Name`, `Description`, `Writes`, `InputSchema`, `Handler`).
- `All()` aggregates the topic’s tools for registration.

### How it is glued together

```
bootstrap → registry.NewRegistry()
         → tools.Register(reg, cfg)
              → <topic>/tool.All()
              → filterTools (default_read_only / whitelist / blacklist)
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
7. Return the plain payload JSON. The runtime sanitizes string values, applies the blacklist (with `DefaultOverrides` for identifier keys), and wraps success results in the `service/security` `{meta, data}` envelope; handlers must not build the envelope themselves. List/search payloads with a top-level `items` array drop rows that fail the blacklist and may include `dropped` (`len(items) + dropped` matches `returned` on that page); pagination fields are not rewritten. Error results (`registry.ErrorResult`) are delivered unwrapped. `Trusted: true` opts a tool out of all of it (server-generated content only, e.g. `mcp-info`); such a tool must check its own PrivX-sourced strings via `security.PrepareStrings`, passing `DefaultOverrides["principal"]` or `DefaultOverrides["name"]` for identifier fields.

Reference topics: `users` (list/search/get + nested role fields), `hosts` (nested service/principal fields).

## Security review

When asked to security-scan this repository, follow [docs/development/security-scan.md](docs/development/security-scan.md). Record findings in the JSON store with `scripts/security-scan-report.py`; regenerate README.md, issues.md, and passed.md with `markdown`. Do not keep the report only in chat. Accepted product behaviour is in [docs/development/security-decisions.md](docs/development/security-decisions.md).

## Project Compatibility Policy

Do not preserve legacy behavior for historical compatibility. Do not add backward-compatibility aliases, shims, or migration layers unless explicitly requested by the user.

Prefer clean, direct implementations and strict configuration/schema validation over compatibility accommodations.

### Documentation and comment language

- Do not use the word "canonical" - it seems to be prevalent among LLMs, but is not often used by people.
- Do not wrap markdown paragraphs with newlines. A paragraph must be one continuous line regardless of editor-defined max line length. Hard-wrapped lines can render poorly depending on the markdown viewer.
