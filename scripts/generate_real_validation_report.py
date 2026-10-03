#!/usr/bin/env python3
"""Generate docs/releases/<candidate>/REAL_VALIDATION.md from the machine
receipt REAL_VALIDATION.json (source of truth).

The Markdown is DERIVED — manual claims without receipts are impossible
by construction: every status line quotes the JSON.

    python scripts/generate_real_validation_report.py \
        --json artifacts/p14/<run_id>/REAL_VALIDATION.json \
        --candidate <label>
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

ALIAS_RE = re.compile(
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})\b")

SECRET_KEYS = re.compile(
    r"(password|passwd|psk|token|secret|private[_ -]?key|auth[_ -]?header)",
    re.I)


def sanitize_text(text: str, aliases: dict[str, str]) -> str:
    out = text
    for real, alias in aliases.items():
        out = out.replace(real, alias)
    out = ALIAS_RE.sub("<redacted-id>", out)
    # key=value secret pairs → key=***REDACTED*** (value never survives);
    # bare tokens (ghp_…, PEM) → ***REDACTED***
    out = re.sub(r"(password|passwd|psk|token|secret)\s*[:=]\s*\S+",
                 lambda m: m.group(1) + "=***REDACTED***", out, flags=re.I)
    out = re.sub(r"ghp_[A-Za-z0-9]{20,}", "***REDACTED***", out)
    out = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
                 r"-----END [A-Z ]*PRIVATE KEY-----", "***REDACTED***", out, flags=re.S)
    return out


def sanitize_obj(obj, aliases: dict[str, str]):
    if isinstance(obj, dict):
        clean = {}
        for k, v in obj.items():
            if SECRET_KEYS.search(str(k)) and isinstance(v, str) and v:
                clean[k] = "***REDACTED***"
            else:
                clean[k] = sanitize_obj(v, aliases)
        return clean
    if isinstance(obj, list):
        return [sanitize_obj(x, aliases) for x in obj]
    if isinstance(obj, str):
        s = sanitize_text(obj, aliases)
        if SECRET_KEYS.search(s) and ":" in s:
            return SECRET_KEYS.sub("***REDACTED***", s)
        return s
    return obj


def status_table(rows: list[dict], name_col: str) -> list[str]:
    lines = ["| " + name_col + " | status | notes |", "|---|---|---|"]
    for r in rows:
        notes = sanitize_obj(r.get("reason") or r.get("detail") or "", {}) \
            if isinstance(r.get("reason") or r.get("detail"), str) else ""
        lines.append(f"| {r.get(name_col, r.get('name', '?'))} "
                     f"| **{r.get('status', '?')}** | {notes} |")
    return lines


def derive(json_path: pathlib.Path, candidate: str) -> tuple[str, dict]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    run_id = data["run_id"]
    aliases = {f"run-{run_id}": run_id[:8]}          # nodes already aliased by runner
    data = sanitize_obj(data, aliases)

    lines = [
        f"# REAL_VALIDATION — {candidate}",
        "",
        f"- run_id: `{run_id}` (machine receipt: `artifacts/p14/{run_id}/`)",
        f"- generated from `REAL_VALIDATION.json` — this file is derived, "
        f"never hand-written.",
        f"- secrets: sanitized; nodes appear only as node-a / node-b / node-c.",
        "",
        "## Stage results",
        "",
        "| stage | status | detail |",
        "|---|---|---|",
    ]
    for stage, info in data.get("stages", {}).items():
        detail = sanitize_text(str(info.get("detail", "")), {})[:160]
        lines.append(f"| {stage} | **{info.get('status', '?')}** | {detail} |")

    by_kind: dict[str, list[dict]] = {}
    for r in data.get("results", []):
        by_kind.setdefault(r["kind"], []).append({"name": r["name"],
                                                  "status": r["status"],
                                                  "reason": r.get("detail", {}).get("reason")})
    for kind, title in (("profile", "Canonical profile matrix"),
                        ("composition", "Composition validation"),
                        ("failover", "Failover validation"),
                        ("multihop", "Multi-hop validation")):
        if kind in by_kind:
            lines += ["", f"## {title}", ""] + status_table(by_kind[kind], "name")

    orphans = data.get("orphans", [])
    lines += ["", "## Orphaned resources",
              "", (f"{len(orphans)} orphan(s) recorded:" if orphans
                   else "None — cleanup complete.")]
    for o in orphans:
        lines.append(f"- `{o.get('resource_id', '?')}` — {o.get('error', '')[:120]}")

    lines += ["", "## Blockers / notes", ""]
    for f in data.get("summary", {}).get("failures", []):
        lines.append(f"- {f}")
    if not data.get("summary", {}).get("failures"):
        lines.append("- none recorded by this run")
    return "\n".join(lines) + "\n", data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True, help="REAL_VALIDATION.json path")
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--out", help="override output md path")
    args = ap.parse_args()

    src = pathlib.Path(args.json)
    md, _data = derive(src, args.candidate)
    out = (pathlib.Path(args.out) if args.out else
           ROOT / "docs" / "releases" / args.candidate / "REAL_VALIDATION.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8", newline="\n")
    # keep a sanitized JSON copy next to the report (the source of truth)
    _md_unused, data = derive(src, args.candidate)
    out.with_name("REAL_VALIDATION.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8", newline="\n")
    print(f"wrote {out} (+ REAL_VALIDATION.json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
