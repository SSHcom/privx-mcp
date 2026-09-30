#!/usr/bin/env python3
"""Timestamped security-scan run directory at the repository root.

    python3 scripts/security-scan-report.py init
    python3 scripts/security-scan-report.py add --severity high --section "Auth edge" --path internal/foo.go --title "..." --why "..." --fix "..."
    python3 scripts/security-scan-report.py ok --section "Auth edge" --title "..." --why "..."
    python3 scripts/security-scan-report.py remove 1
    python3 scripts/security-scan-report.py skip --tool gitleaks --reason "not on PATH"
    python3 scripts/security-scan-report.py unskip --tool gitleaks
    python3 scripts/security-scan-report.py note "put TLS in front of the binary"
    python3 scripts/security-scan-report.py import < entries.jsonl
    python3 scripts/security-scan-report.py show
    python3 scripts/security-scan-report.py markdown [security-scan-... | scan.json]

JSON (scan.json) is the working store for agents. People read README.md, issues.md, and passed.md in the same directory.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STORE_NAME = "scan.json"
RUN_DIR_PREFIX = "security-scan-"
LEGACY_POINTER = REPO_ROOT / "security-scan.latest"
SEVERITIES = ("critical", "high", "medium", "low")
SECTIONS = (
    "Auth edge",
    "PrivX impersonation",
    "Authorization",
    "MCP data boundary",
    "Handler trust",
    "Secrets and logs",
    "Proxy",
    "Optional scanners",
)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def store_in_dir(directory: Path) -> Path:
    path = directory / STORE_NAME
    if not path.is_file():
        raise SystemExit(f"no {STORE_NAME} in {directory}")
    return path


def newest_run_dir() -> Path | None:
    runs = [
        p
        for p in REPO_ROOT.glob(RUN_DIR_PREFIX + "*")
        if p.is_dir() and (p / STORE_NAME).is_file()
    ]
    if not runs:
        return None
    return max(runs, key=lambda p: p.name)


def resolve_store(explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).resolve()
        if path.is_dir():
            return store_in_dir(path)
        if path.is_file():
            return path
        raise SystemExit(f"not found: {path}")
    directory = newest_run_dir()
    if directory is None:
        raise SystemExit("no security-scan-* run directory; call init first")
    return store_in_dir(directory)


def git_head() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return out.strip()


def next_id(data: dict) -> int:
    fid = data["next_id"]
    data["next_id"] = fid + 1
    return fid


def empty_store(stamp: str) -> dict:
    return {
        "started": stamp,
        "git": git_head(),
        "next_id": 1,
        "findings": [],
        "checked": [],
        "skipped": [],
        "notes": [],
    }


def cmd_init(_args: argparse.Namespace) -> None:
    stamp = utc_stamp()
    directory = REPO_ROOT / f"{RUN_DIR_PREFIX}{stamp}"
    directory.mkdir()
    path = directory / STORE_NAME
    save(path, empty_store(stamp))
    LEGACY_POINTER.unlink(missing_ok=True)
    print(directory)


def cmd_add(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    fid = next_id(data)
    data["findings"].append(
        {
            "id": fid,
            "severity": args.severity,
            "section": args.section,
            "path": args.path or "",
            "title": args.title,
            "why": args.why,
            "fix": args.fix or "",
        }
    )
    save(path, data)
    print(fid)


def cmd_ok(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    data.setdefault("checked", [])
    fid = next_id(data)
    data["checked"].append(
        {
            "id": fid,
            "section": args.section,
            "path": args.path or "",
            "title": args.title,
            "why": args.why,
        }
    )
    save(path, data)
    print(fid)


def cmd_remove(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    findings_before = len(data["findings"])
    checked_before = len(data.get("checked", []))
    data["findings"] = [f for f in data["findings"] if f["id"] != args.id]
    data["checked"] = [c for c in data.get("checked", []) if c["id"] != args.id]
    if len(data["findings"]) + len(data["checked"]) == findings_before + checked_before:
        raise SystemExit(f"no finding {args.id}")
    save(path, data)


def cmd_skip(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    data["skipped"].append({"tool": args.tool, "reason": args.reason})
    save(path, data)


def cmd_unskip(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    before = len(data["skipped"])
    data["skipped"] = [s for s in data["skipped"] if s.get("tool") != args.tool]
    if len(data["skipped"]) == before:
        raise SystemExit(f"no skip for {args.tool!r}")
    save(path, data)


def cmd_note(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    data["notes"].append(args.text)
    save(path, data)


def apply_import_row(data: dict, row: dict) -> None:
    op = row.get("op")
    if op == "add":
        fid = next_id(data)
        data["findings"].append(
            {
                "id": fid,
                "severity": row["severity"],
                "section": row["section"],
                "path": row.get("path") or "",
                "title": row["title"],
                "why": row["why"],
                "fix": row.get("fix") or "",
            }
        )
    elif op == "ok":
        data.setdefault("checked", [])
        fid = next_id(data)
        data["checked"].append(
            {
                "id": fid,
                "section": row["section"],
                "path": row.get("path") or "",
                "title": row["title"],
                "why": row["why"],
            }
        )
    elif op == "skip":
        data["skipped"].append({"tool": row["tool"], "reason": row["reason"]})
    elif op == "note":
        data["notes"].append(row["text"])
    else:
        raise SystemExit(f"unknown import op: {op!r}")


def cmd_import(args: argparse.Namespace) -> None:
    path = resolve_store(args.file)
    data = load(path)
    n = 0
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        apply_import_row(data, json.loads(line))
        n += 1
    save(path, data)
    print(n)


def extra_sections(data: dict) -> list[str]:
    extra: list[str] = []
    known = set(SECTIONS)
    for item in list(data.get("findings", [])) + list(data.get("checked", [])):
        name = item.get("section") or ""
        if name and name not in known and name not in extra:
            extra.append(name)
    return extra


def ordered_sections(data: dict, items: list[dict]) -> list[str]:
    names = {item.get("section") or "" for item in items}
    names.discard("")
    seen: list[str] = []
    for name in list(SECTIONS) + extra_sections(data):
        if name in names:
            seen.append(name)
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


def issue_counts(findings: list[dict]) -> str:
    counts = [f"{n} {sev}" for sev in SEVERITIES if (n := sum(1 for f in findings if f["severity"] == sev))]
    if counts:
        return "Issues: " + ", ".join(counts) + "."
    return "Issues: none."


def render_issue(f: dict) -> list[str]:
    lines = [f"### Issue {f['id']} ({f['severity']}): {f['title']}"]
    if f.get("path"):
        lines.append(f"- Path: {f['path']}")
    lines.append(f"- Why: {f['why']}")
    if f.get("fix"):
        lines.append(f"- Fix: {f['fix']}")
    lines.append("")
    return lines


def render_passed(c: dict) -> list[str]:
    lines = [f"### Passed {c['id']}: {c['title']}"]
    if c.get("path"):
        lines.append(f"- Path: {c['path']}")
    if c.get("why"):
        lines.append(f"- Why: {c['why']}")
    lines.append("")
    return lines


def heading(data: dict, subtitle: str) -> list[str]:
    lines = [f"# Security scan {data['started']}", "", subtitle, ""]
    if data.get("git"):
        lines.append(f"Git: `{data['git']}`")
        lines.append("")
    return lines


def render_readme(data: dict) -> str:
    findings = data.get("findings") or []
    checked = data.get("checked") or []
    lines = heading(
        data,
        "Summary of this run. Defects are in [issues.md](issues.md). Checks that held (no defect) are in [passed.md](passed.md). Accepted product behaviour (not defects) is in [docs/development/security-decisions.md](../docs/development/security-decisions.md); when triaging issues.md, add an entry there for anything you accept rather than fix.",
    )
    lines.append(issue_counts(findings))
    lines.append(f"Passed: {len(checked)}.")
    lines.append(f"Skipped: {len(data.get('skipped') or [])}.")
    lines.append("")
    if data.get("skipped"):
        lines.append("## Skipped")
        lines.append("")
        for s in data["skipped"]:
            lines.append(f"- {s['tool']}: {s['reason']}")
        lines.append("")
    if data.get("notes"):
        lines.append("## Notes")
        lines.append("")
        for n in data["notes"]:
            lines.append(f"- {n}")
        lines.append("")
    if not findings and not checked and not data.get("skipped") and not data.get("notes"):
        lines.append("(empty)")
        lines.append("")
    return "\n".join(lines)


def render_issues(data: dict) -> str:
    findings = data.get("findings") or []
    lines = heading(data, "Defects only. Checks that held are in [passed.md](passed.md).")
    lines.append(issue_counts(findings))
    lines.append("")
    if not findings:
        lines.append("No issues recorded.")
        lines.append("")
        return "\n".join(lines)
    for section in ordered_sections(data, findings):
        lines.append(f"## {section}")
        lines.append("")
        for f in findings:
            if f.get("section") == section:
                lines.extend(render_issue(f))
    return "\n".join(lines)


def render_passed_md(data: dict) -> str:
    checked = data.get("checked") or []
    lines = heading(data, "Checks that held: no defect found. Defects are in [issues.md](issues.md).")
    lines.append(f"Passed: {len(checked)}.")
    lines.append("")
    if not checked:
        legacy = data.get("clean") or []
        if legacy:
            for name in legacy:
                lines.append(f"## {name}")
                lines.append("")
                lines.append("Passed: no issue.")
                lines.append("")
            return "\n".join(lines)
        lines.append("No passed checks recorded.")
        lines.append("")
        return "\n".join(lines)
    for section in ordered_sections(data, checked):
        lines.append(f"## {section}")
        lines.append("")
        for c in checked:
            if c.get("section") == section:
                lines.extend(render_passed(c))
    return "\n".join(lines)


def write_people_report(store: Path) -> Path:
    data = load(store)
    directory = store.parent
    (directory / "README.md").write_text(render_readme(data), encoding="utf-8")
    (directory / "issues.md").write_text(render_issues(data), encoding="utf-8")
    (directory / "passed.md").write_text(render_passed_md(data), encoding="utf-8")
    return directory


def cmd_show(args: argparse.Namespace) -> None:
    sys.stdout.write(render_readme(load(resolve_store(args.file))))


def cmd_markdown(args: argparse.Namespace) -> None:
    src = resolve_store(args.json)
    print(write_people_report(src))


def cmd_self_check(_args: argparse.Namespace) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp) / "security-scan-t"
        directory.mkdir()
        store = directory / STORE_NAME
        save(store, empty_store("t") | {"git": ""})
        add_ns = argparse.Namespace(
            file=str(store),
            severity="high",
            section="Auth edge",
            path="internal/x.go",
            title="open /mcp",
            why="no bearer",
            fix="require JWT",
        )
        cmd_add(add_ns)
        cmd_ok(
            argparse.Namespace(
                file=str(store),
                section="Auth edge",
                path="internal/x.go",
                title="JWKS still required on other paths",
                why="only this handler is open",
            )
        )
        data = load(store)
        assert data["findings"][0]["id"] == 1
        assert data["checked"][0]["id"] == 2
        cmd_remove(argparse.Namespace(file=str(store), id=1))
        cmd_skip(argparse.Namespace(file=str(store), tool="gitleaks", reason="missing"))
        cmd_unskip(argparse.Namespace(file=str(store), tool="gitleaks"))
        cmd_skip(argparse.Namespace(file=str(store), tool="gitleaks", reason="missing"))
        cmd_note(argparse.Namespace(file=str(store), text="use a reverse proxy"))
        out_dir = write_people_report(store)
        assert out_dir == directory
        readme = (directory / "README.md").read_text(encoding="utf-8")
        issues = (directory / "issues.md").read_text(encoding="utf-8")
        passed = (directory / "passed.md").read_text(encoding="utf-8")
        assert "Issues: none." in readme
        assert "docs/development/security-decisions.md" in readme
        assert "gitleaks: missing" in readme
        assert "use a reverse proxy" in readme
        assert "Passed 2:" in passed
        assert "JWKS still required" in passed
        assert "### Issue" not in passed
        assert "No issues recorded." in issues
        assert "Passed 2:" not in issues
        cmd_add(add_ns)
        write_people_report(store)
        issues = (directory / "issues.md").read_text(encoding="utf-8")
        passed = (directory / "passed.md").read_text(encoding="utf-8")
        assert "### Issue 3 (high): open /mcp" in issues
        assert "Passed 2:" in passed
        assert "open /mcp" not in passed
    print("ok")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Record a security-scan run directory at the repository root.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def store_flag(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--file", help="JSON store or run directory (default: newest security-scan-* directory)")

    sp = sub.add_parser("init", help="start a new timestamped run directory")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("add", help="add an issue")
    store_flag(sp)
    sp.add_argument("--severity", required=True, choices=SEVERITIES)
    sp.add_argument("--section", required=True)
    sp.add_argument("--path", default="")
    sp.add_argument("--title", required=True)
    sp.add_argument("--why", required=True)
    sp.add_argument("--fix", default="")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("ok", help="add a passed check (no defect)")
    store_flag(sp)
    sp.add_argument("--section", required=True)
    sp.add_argument("--title", required=True)
    sp.add_argument("--why", required=True)
    sp.add_argument("--path", default="")
    sp.set_defaults(func=cmd_ok)

    sp = sub.add_parser("remove", help="remove an issue or passed check by id")
    store_flag(sp)
    sp.add_argument("id", type=int)
    sp.set_defaults(func=cmd_remove)

    sp = sub.add_parser("skip", help="record a skipped checker")
    store_flag(sp)
    sp.add_argument("--tool", required=True)
    sp.add_argument("--reason", required=True)
    sp.set_defaults(func=cmd_skip)

    sp = sub.add_parser("unskip", help="drop a skip record by tool name")
    sp.add_argument("--tool", required=True)
    store_flag(sp)
    sp.set_defaults(func=cmd_unskip)

    sp = sub.add_parser("note", help="operator appendix (not a topic entry)")
    store_flag(sp)
    sp.add_argument("text")
    sp.set_defaults(func=cmd_note)

    sp = sub.add_parser("import", help="apply JSONL ops from stdin (add/ok/skip/note)")
    store_flag(sp)
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("show", help="print README.md to stdout")
    store_flag(sp)
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("markdown", help="write README.md, issues.md, and passed.md in the run directory")
    sp.add_argument("json", nargs="?", help="run directory or scan.json (default: newest security-scan-* directory)")
    sp.set_defaults(func=cmd_markdown)

    sp = sub.add_parser("self-check", help="run a tiny in-tempdir check")
    sp.set_defaults(func=cmd_self_check)
    return p


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
