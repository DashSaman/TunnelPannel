"""Telegram bot core (P12 §22-§23) — transport-agnostic, canonical-API-only.

BotCore never implements networking logic: it formats state fetched from
the canonical API. Authorization is enforced per Telegram identity BEFORE
any action; dangerous actions need an explicit confirmation token. Secrets
are structurally redacted — tokens/passwords never leave the core.
"""
from __future__ import annotations

import re
import secrets

SECRET_PATTERNS = [
    re.compile(r"(password|token|psk|secret|key)\s*[:=]\s*\S+", re.I),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def redact(text: str) -> str:
    out = text
    for pat in SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(0).split(":", 1)[0].split("=", 1)[0] + "=***REDACTED***"
                      if (":" in m.group(0) or "=" in m.group(0)) else "***REDACTED***", out)
    return out


class NotAuthorized(RuntimeError):
    pass


class ConfirmationRequired(RuntimeError):
    pass


class BotCore:
    """Commands: /status /nodes /benchmarks /paths /failover /alerts
    /maintenance. api is any object with .get(path)->dict (thin canonical
    API client). Dangerous: /maintenance <id> on, /failover pin — both
    demand a confirmation token issued by the bot itself."""

    DANGEROUS = {"maintenance", "pin"}

    def __init__(self, api, allowed_user_ids: set[int], now=None):
        self.api = api
        self.allowed = set(allowed_user_ids)
        self._pending: dict[str, dict] = {}       # token -> pending action
        self._now = now or (lambda: 0.0)

    # ── authorization (§23) ──
    def _auth(self, user_id: int) -> None:
        if user_id not in self.allowed:
            raise NotAuthorized(f"user {user_id} is not authorized")

    # ── command dispatch ──
    def handle(self, user_id: int, text: str) -> str:
        self._auth(user_id)
        parts = text.strip().split()
        cmd = parts[0].lstrip("/").split("@")[0].lower()
        args = parts[1:]
        handlers = {
            "start": self._status, "status": self._status,
            "nodes": self._nodes, "benchmarks": self._benchmarks,
            "paths": self._paths, "failover": self._failover,
            "alerts": self._alerts, "maintenance": self._maintenance,
            "confirm": self._confirm,
        }
        handler = handlers.get(cmd)
        if handler is None:
            return ("commands: /status /nodes /benchmarks /paths /failover "
                    "/alerts /maintenance — dangerous actions need /confirm")
        return redact(handler(args))

    # ── handlers (formatting only; data from canonical API) ──
    def _status(self, args):
        d = self.api.get("/api/status")
        return (f"⚡ TunnelPannel\nmode: {d.get('mode', '?')} · "
                f"active: {d.get('active', '—')} · "
                f"UP/total: {d.get('up', '?')}/{d.get('total', '?')} · "
                f"alerts: {d.get('active_alerts', 0)}")

    def _nodes(self, args):
        nodes = self.api.get("/api/nodes")
        if not nodes:
            return "no nodes registered yet"
        return "\n".join(f"• {n['name']} ({n['host']})" for n in nodes[:20])

    def _benchmarks(self, args):
        runs = self.api.get("/benchmarks")
        if not runs:
            return "no benchmark runs yet"
        return "\n".join(f"• {r['job_id'][:8]} [{r.get('state')}] "
                         f"{r.get('compatible', '?')} compatible" for r in runs[:10])

    def _paths(self, args):
        topo = self.api.get("/api/topology")
        edges = topo.get("edges", [])
        if not edges:
            return "topology empty — add edges in the panel"
        return "\n".join(f"• {e['from_node']} → {e['to_node']} via {e['route']}"
                         for e in edges[:20])

    def _failover(self, args):
        groups = self.api.get("/failover-groups")
        if not groups:
            return "no failover groups"
        out = []
        for g in groups[:10]:
            out.append(f"• {g['name']}: active={g.get('active') or '—'} "
                       f"[{g.get('mode')}]")
        if args and args[0] == "pin" and len(args) >= 2:
            token = secrets.token_hex(4)
            self._pending[token] = {"action": "pin", "group": args[1],
                                    "user": None}
            out.append(f"⚠ dangerous: reply /confirm {token} to pin group {args[1]}")
        return "\n".join(out)

    def _alerts(self, args):
        alerts = self.api.get("/api/alerts/active")
        if not alerts:
            return "no active alerts ✅"
        return "\n".join(f"• [{a['severity']}] {a['kind']} {a.get('key', '')} "
                         f"x{a.get('occurrences', 1)}" for a in alerts[:20])

    def _maintenance(self, args):
        if not args:
            return "usage: /maintenance <node-or-route> on|off"
        token = secrets.token_hex(4)
        self._pending[token] = {"action": "maintenance", "target": args[0],
                                "state": args[1] if len(args) > 1 else "on"}
        return (f"⚠ dangerous: set maintenance={self._pending[token]['state']} "
                f"for {args[0]}? reply /confirm {token}")

    def _confirm(self, args):
        if not args or args[0] not in self._pending:
            raise ConfirmationRequired("no pending action — issue the command first")
        pending = self._pending.pop(args[0])
        if pending["action"] == "maintenance":
            result = self.api.post("/api/maintenance",
                                   {"target": pending["target"],
                                    "on": pending["state"] == "on"})
            return redact(f"maintenance {pending['state']} → {result}")
        if pending["action"] == "pin":
            result = self.api.post(f"/failover-groups/{pending['group']}/pin",
                                   {"member_index": None})
            return redact(f"pin released → {result}")
        return "unknown action"

    # ── notification formatting (§25 failover event notification) ──
    def format_switch(self, receipt: dict) -> str:
        return redact(
            f"🔀 failover: {receipt.get('frm')} → {receipt.get('to')} "
            f"[{receipt.get('actor')}] {receipt.get('reason', '')}")

    def format_notification(self, text: str) -> str:
        return redact(f"🚨 {text}")
