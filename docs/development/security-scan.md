# Security scan (this repository)

Agent and human instruction for reviewing **this** process: an HTTP MCP resource server (`cmd/privx-mcp-server`) and a stdio OAuth proxy (`cmd/privx-mcp-proxy`). The product is the binary. How an operator hosts it (Docker, systemd, bind address, firewall, TLS at a reverse proxy) is out of scope as findings.

Walk the trust chain in the code. Optional tools on `PATH` may add secrets and dependency CVEs; they do not replace reading that chain. The checklist below is a floor: known claims to verify, not the set of paths you are allowed to look at.

Threat model and intended controls: [security.md](../manual/reference/security/security.md), [user_level_security.md](../manual/reference/security/user_level_security.md). Accepted product behaviour: [security-decisions.md](security-decisions.md). Package layout: [AGENTS.md](../../AGENTS.md). If the threat-model docs and the code disagree, the code is what you scan. Do not rewrite this file during the scan.

## Operating rules

1. Read-only on application code. Do not edit sources to "fix" the scan while scanning.
2. Do not fabricate findings. If you did not inspect a path or a tool was not run, say so.
3. Never print secret values. Path, rule id, and a redacted fingerprint only.
4. Fail-soft. One missing or crashing checker does not abort the review.
5. Do not install tools, print install commands, or name a package manager. `command -v` each optional binary. `skip` if it is absent **or** if it is present and then fails (crash, OOM, toolchain mismatch). One `skip` per table row; put the failure in `--reason`. Do not invent extra tool names for a sub-step.
6. Honour `.gitignore`. Skip untracked local files and operator secrets (live config, keys, env). Example configs that are in git are in scope only as **examples** (no live secrets).
7. Read [security-decisions.md](security-decisions.md) before scoring. A match is not an issue; `ok` it if passed checks were requested. Do not `add` it again unless the code no longer matches the decision. If a later change fixes or alters a decided item, rewrite or delete that entry in the same change.
8. Before `init`, ask whether the people report should include **passed** checks as well as **issues**. If yes, call `ok` for each check. If no, call `add` for issues only. If they already said in the same message, do not re-ask.
9. Start from the tree, not from the bullets. For each section, open the packages the trust chain actually uses and follow callers; then score the bullets against what you found. Stopping at named files or flags is how this scan goes stale. A claimed control that is missing or weaker in code is a product issue. A security-relevant path, flag, or tool the checklist never mentions is a product issue if it is unsafe, and always an issue against this file: `add` with path `docs/development/security-scan.md` (title that this file needs updating, why the gap, fix: add a bullet). A named mechanism that is gone from the tree is the same path (fix: drop the bullet); do not invent a product defect against a removed control. The same `add` applies to the scan process itself: an operating rule, checklist step, scanner table row, or `scripts/security-scan-report.py` behaviour that is wrong, contradictory, or cannot be followed. Path is this file or the script, whichever needs the change. Do not leave process defects only in chat.

## Do not

- Treat Dockerfiles, compose, or systemd as the deployment model or raise container/image/IaC findings.
- Raise network posture (listen address, TLS termination, unauthenticated flood) as defects. Put those in Notes (operator appendix) only, unless a **code default** is unsafe with no operator action.
- Scan PrivX itself or the IdP.

## Trust chain

```
MCP client --bearer--> /mcp (JWKS) --> rate limit --> RSA JWT mint --> PrivX as that user --> PermissionEngine --> tool handler --> sanitize / blacklist / envelope
```

## Checklist

Work in this order. Cite file and what broke (or what you verified) in the chain. Documented, intentional behaviour is not an issue; record it as `ok` when passed checks were requested. Judge the code you opened, not only the bullets (operating rule 9). The threat-model docs explain intent; they are not a substitute for following the chain.

After each section, `add` each issue. If passed checks were requested, also `ok` each distinct check or judgement. A section may have both. Do not dump checks into `note`. Prefer `import` (JSONL on stdin) over dozens of separate `add` / `ok` process calls.

### 1. Auth edge

Read the HTTP MCP transport and OAuth verification (including well-known / DCR if present).

- The MCP HTTP endpoint requires a verified bearer when a public URL is configured (`iss`, `aud`, `exp`, JWKS). A loaded production config must not be able to skip that wrap.
- A DCR stub must not put `client_secret` where a client should not see it. Returning it on `POST /register` is the DCR contract; it must not appear in OAuth metadata.
- Dev or passthrough auth flags stay unwired unless clearly documented as unsafe.

### 2. PrivX impersonation

Read PrivX token minting, exchange, and how the signing key is loaded.

- The RSA private key is loaded from a configured path, not baked into the binary.
- Minted JWT `iss`, `sub`, `exp` match what PrivX External Token Provider must trust. `aud` is omitted when unset. `kid` is the JWT **header**, not a claim.
- Service API credentials (permission lookup) are distinct from the per-user connector. The lookup uses the API client because the signed-in user may lack permission to read their own roles and permissions. A tool call must still run as that user, not as the API client.
- The PrivX user named by the minted JWT must be the user whose roles are checked. The first call compares those user ids and refuses a mismatch. A different token subject must not reuse that cached match.

### 3. Authorization

Read tool registration, permission mapping, and the MCP runtime.

- Write tools are dropped when read-only mode is on. A mutating tool classified as non-writing is an issue unless the product docs call that out as an exception; if they do, record the judgement as `ok`.
- A tool with no required PrivX scopes is listed and judged: any authenticated caller can invoke it. Record that as `ok` on this section, not as Notes.
- Trusted tools are for server-generated content only. A Trusted tool that mixes in PrivX-sourced strings must run the same string hardening the runtime uses for everyone else.
- Session cache TTL: a stale **allow** after revoke until TTL expires is documented; a stale allow that never expires is an issue.

### 4. MCP data boundary

Read the MCP security package and the runtime that applies it on tool calls.

- Non-Trusted tools: inbound hardening on params; outbound sanitize, blacklist, envelope.
- List/search: drop failing `items` rows; single-object get withholds the whole payload; do not name the blocked word on the way out.
- Blacklist exceptions stay key-scoped and match [security.md](../manual/reference/security/security.md). Injection terms are not excepted on fields where that document still blocks them.
- Homoglyph / non-English instruction gaps are known limits in `security.md`, not new issues unless a bypass is worse than documented.

### 5. Handler trust

On a first full-repo scan, sample several resource topics (see AGENTS.md for layout), including mutating tools. That is enough; do not read every handler. On later scans, focus on tools added or changed since the last scan's git commit.

- Params are parsed with typed helpers: wrong types must not silently write zeros into PrivX where that would be dangerous.
- Unknown keys must not reach the API except documented opaque-JSON fields.
- The write flag matches mutation. Redact passwords, keys, and similar from tool responses.

### 6. Secrets and logs

- Config loaders: secrets from TOML/env/files, not logs.
- `.gitignore` covers live config and key material.
- MCP client must not see omitted-row bodies or bearer tokens. Server logs that help an operator clean a blacklisted record are fine if the client never sees them.

### 7. Proxy

Read the stdio proxy (`cmd/privx-mcp-proxy` and its packages).

- Token store and client secret handling.
- Unsafe **defaults** in code (for example allowing cleartext HTTP without the operator setting it) are issues. The operator choosing a bind address is not.

## Tests

Always run `task test` or `go test ./...` when `go` is on PATH. Record under section `Optional scanners` (no extra section). A pass is `ok`. A fail is an `add`: the tree does not currently hold its own checks. `skip` only if `go` is missing.

## Optional scanners

If present, run and merge into the same store under section `Optional scanners`. Deduplicate: one CVE from `govulncheck` + `osv-scanner` + `trivy` is one issue. Prefer standalone `govulncheck ./...` for **reachable** Go vulns: a module hit that is not called is not an issue (mention it on an `ok` entry if passed checks were requested).

`osv-scanner` tries to run govulncheck itself for call analysis. That embedded binary is often built with a different Go than `PATH`, and then the reachability pass fails even when `osv-scanner` is installed. Run `govulncheck` from `PATH` as the source of truth; keep osv-scanner for the lockfile list. If the embedded pass fails, still record the lockfile result (or `skip` the osv-scanner **row** with that reason). Do not add a second skip named after the embedded binary.

Lint (`golangci-lint` / `task lint`) is hygiene. Record it as `ok` or `skip`, not as issues, unless a hit is security-relevant. Style-only hits are not findings.

Successful scanners do not need a separate "ran" list: a clean run is an `ok` on this section; a failure to execute is `skip` and shows up in README.md.

| If on PATH  | Command                                                                                  | Notes                                                                                                       |
| ----------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| lint        | `task lint` or `golangci-lint run ./...`                                                 | Hygiene. `ok` or `skip`; security-relevant hits only as issues.                                             |
| govulncheck | `govulncheck ./...`                                                                      | Reachable Go vulns. Source of truth for call analysis. Unreachable module hits are `ok`, not issues.        |
| gitleaks    | `gitleaks detect --redact` (git history; not `--no-git`)                                 | Secrets in tracked git. Untracked operator files stay out. Never print matches.                             |
| osv-scanner | `osv-scanner scan source -r .`                                                           | Lockfile CVEs in `go.mod` / `go.sum`. Ignore a failed embedded govulncheck; use PATH `govulncheck` instead. |
| trivy       | `trivy fs --scanners vuln --pkg-types library .` plus `--skip-dirs` for gitignored trees | Go module vulns only. Dedup with govulncheck/osv-scanner. Hits under gitignored trees are out of scope.     |
| syft        | `syft scan dir:. -o cyclonedx-json --select-catalogers golang`                           | Write `sbom.cdx.json` in the run directory (gitignored). Do not paste the SBOM in chat.                     |
| semgrep     | `semgrep scan --config p/golang --use-git-ignore`                                        | Go rules only. If it crashes or produces no results, `skip` the row; do not invent findings.                |

## Report format

One gitignored directory per run: `security-scan-<UTC-timestamp>/`. JSON is the working store for agents (`scan.json`): read it, then `add` / `ok` / `remove` / `skip` / `unskip` / `note` / `import`. Markdown is for people and must not mix defects with passing checks:

| File        | Contents                                                                                                                   |
| ----------- | -------------------------------------------------------------------------------------------------------------------------- |
| `README.md` | Counts, skipped tools, operator notes. Links to the other two files and to [security-decisions.md](security-decisions.md). |
| `issues.md` | Defects only (`add`).                                                                                                      |
| `passed.md` | Checks that held (`ok`). These are not failures.                                                                           |

Regenerate the three files with `markdown` after you change the JSON. Do not keep the report in chat and do not hand-edit the `.md` files.

`init` creates the directory (git HEAD when `git` works). Later commands use the newest `security-scan-*` directory unless you pass a path. If `python3` is missing, skip the helper and write JSON-equivalent entries in the reply so a person can still read them.

```
python3 scripts/security-scan-report.py init
python3 scripts/security-scan-report.py add --severity high --section "Auth edge" --path internal/foo.go --title "..." --why "..." --fix "..."
python3 scripts/security-scan-report.py ok --section "Auth edge" --path internal/foo.go --title "..." --why "..."
python3 scripts/security-scan-report.py import <<'EOF'
{"op":"ok","section":"Auth edge","path":"internal/foo.go","title":"...","why":"..."}
{"op":"skip","tool":"semgrep","reason":"scanner crashed"}
{"op":"note","text":"put TLS in front of the binary"}
EOF
python3 scripts/security-scan-report.py remove 1
python3 scripts/security-scan-report.py skip --tool gitleaks --reason "not on PATH"
python3 scripts/security-scan-report.py unskip --tool gitleaks
python3 scripts/security-scan-report.py note "put TLS in front of the binary"
python3 scripts/security-scan-report.py markdown
python3 scripts/security-scan-report.py markdown security-scan-2026-09-16T115029Z
```

`ok` means the check passed (no defect). If passed checks were not requested, do not call `ok`; then `passed.md` stays empty and README still has issues, skips, and notes.

`note` is the operator appendix only (README.md). After scanners, `skip` or `add` (deduped CVEs) or `ok` for a clean/reachable-empty run. `unskip` if a skipped tool is run later in the same run. End by running `markdown`, telling the reader the run directory path, then [What to do next](#what-to-do-next). Use `show` only if you need a stdout peek of README.md; prefer reading the files.

Issue fields: severity (`critical` / `high` / `medium` / `low`), section, path, title (what broke), why it matters here, fix. Passed fields: section, path, title (what was verified), why.

## Operator recommendations (not issues)

These belong in Notes unless a code default is already unsafe:

- Run the binary behind TLS or a reverse proxy; do not expose the RSA signing key or API credentials on a workstation against production PrivX ([security.md](../manual/reference/security/security.md)).
- Protect signing keys and PrivX API client secrets on disk.
- Demo compose passwords and local IdP defaults are for demonstration only.
- Unauthenticated load and bind address are a proxy or host problem; in-process rate limits apply only after a valid identity on `tools/call`.

## What to do next (if you are an agent)

End the scan by telling the user what to do next, under that heading:

1. Check the findings in `issues.md` of the run directory.
2. Discuss them with an agent in a new session. This scan session has built up a big LLM context, so do not continue here.
3. For each finding, find out whether it really is an issue. Fix the ones that are.
4. For the ones that are not (accepted product behaviour, false positive), add an entry to [security-decisions.md](security-decisions.md) so that future scans skip raising them as issues.
