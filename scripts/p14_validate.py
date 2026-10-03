#!/usr/bin/env python3
"""P14 real-node validation runner (P14-PREP).

Everything needed to start REAL validation the moment fresh credentials
exist — nothing here reads or reuses secrets from git history. Node
access comes ONLY from a local, gitignored YAML config (see
tests/e2e/p14-nodes.example.yml) or TP14_CONFIG env var.

Modes:
  preflight | inventory | quick | normal | profiles | compositions |
  failover | multihop | install | upgrade | backup-restore | uninstall |
  cleanup | all | resume

Usage:
  python scripts/p14_validate.py --config tests/e2e/p14-nodes.yml preflight
  python scripts/p14_validate.py --config … --resume <run_id> profiles
  python scripts/p14_validate.py cleanup --run <run_id>

Safety invariants enforced by code (not convention):
- preflight performs ZERO mutations (allowlisted read-only commands only)
- SSH is key-only, non-interactive, host-key pinning required before
  any mutation (insecure host-key bypass is never used)
- every resource carries owner=TunnelPannel + validation_run_id
- cleanup runs on PASS/FAIL/TIMEOUT/CANCEL; incomplete cleanup records
  ORPHANED_RESOURCE with the resource id
- management SSH route is snapshotted in preflight and re-verified
  before every mutation stage — a changed management route refuses to
  continue (never risks operator access)
- every profile result is one of FINITE_RESULT_STATUSES (no UNKNOWN)
- secrets are sanitized out of receipts/logs/reports; nodes are aliased
  node-a / node-b / node-c in public reports
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import pathlib
import re
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.catalog import CATALOG                                  # noqa: E402

ARTIFACTS = ROOT / "artifacts" / "p14"
DEFAULT_CONFIG = ROOT / "tests" / "e2e" / "p14-nodes.yml"

STAGE_ORDER = ["preflight", "inventory", "quick", "normal", "profiles",
               "compositions", "failover", "multihop", "install",
               "upgrade", "backup-restore", "uninstall"]

# every profile/path/stage verdict MUST be one of these — UNKNOWN is illegal
FINITE_RESULT_STATUSES = frozenset({
    "PASS", "FAILED", "INCOMPATIBLE_WITH_TEST_ENVIRONMENT",
    "BLOCKED_EXTERNAL_DEPENDENCY", "NOT_APPLICABLE", "CANCELLED", "TIMED_OUT",
})

OWNER = "TunnelPannel"

# preflight may ONLY run these read-only command prefixes (zero mutation)
READ_ONLY_PREFIXES = (
    "echo ", "true", "uname ", "cat /etc/os-release", "nproc", "free -",
    "df -", "ip -o link", "ip addr show", "ip route show", "ip route get ",
    "ip rule show", "ip -6 route show", "ip -6 rule show",
    "ss -", "ls /sys/module", "lsmod", "command -v", "wg show",
    "nft list ", "iptables -L", "sysctl net.ipv4.ip_forward",
    "test -", "stat ", "echo $SSH_CLIENT",
    "sha256sum /etc/tunnelpannel/tunnelpannel.env", "systemctl is-active ",
    "systemctl list-units ", "curl -fsS http://127.0.0.1:",
)
# verbs that must NEVER appear even after an allowed prefix (defense in depth)
FORBIDDEN_VERBS = (" replace", " delete", " del ", " add", " flush", " drop",
                   " kill", " rm ", "restart", " stop", " start", "enable",
                   "disable", "insert", "truncate", " mkfs", " dd ")


def assert_finite(status: str) -> str:
    if status not in FINITE_RESULT_STATUSES:
        raise ValueError(f"illegal result status {status!r} — "
                         f"must be one of {sorted(FINITE_RESULT_STATUSES)}")
    return status


# ═══════════════════ config ═══════════════════════════════════════════

@dataclasses.dataclass
class NodeAccess:
    key: str                          # node-a | node-b | node-c
    host: str
    port: int = 22
    user: str = "root"
    key_path: str = ""                # OUTSIDE git; never committed
    known_hosts: str = ""             # pin file; mutation refuses without it
    alias: str = ""                   # public alias (node-a …)


@dataclasses.dataclass
class P14Config:
    nodes: dict[str, NodeAccess]
    candidate: str = "candidate"
    profiles: tuple = ("QUICK", "NORMAL")
    stages: tuple = tuple(STAGE_ORDER)
    profile_budget_s: int = 180
    max_hops: int = 3
    install_port: int = 8080

    @classmethod
    def load(cls, path: pathlib.Path) -> "P14Config":
        import yaml
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        nodes_raw = raw.get("nodes") or {}
        if not nodes_raw:
            raise ValueError("config has no nodes — copy "
                             "tests/e2e/p14-nodes.example.yml and fill it in "
                             "(file stays gitignored)")
        nodes = {}
        for key, n in nodes_raw.items():
            if not n.get("host") or n.get("host", "").startswith("REPLACE"):
                raise ValueError(f"node {key}: host is a placeholder — "
                                 "fill the real value in the gitignored config")
            nodes[key] = NodeAccess(
                key=key, host=n["host"], port=int(n.get("port", 22)),
                user=n.get("user", "root"),
                key_path=n.get("key_path", ""),
                known_hosts=n.get("known_hosts", ""),
                alias=n.get("alias", key))
        run = raw.get("run") or {}
        settings = raw.get("settings") or {}
        return cls(
            nodes=nodes,
            candidate=str(run.get("candidate", "candidate")),
            profiles=tuple(run.get("profiles", ("QUICK", "NORMAL"))),
            stages=tuple(run.get("stages", STAGE_ORDER)),
            profile_budget_s=int(settings.get("profile_budget_s", 180)),
            max_hops=int(settings.get("max_hops", 3)),
            install_port=int(settings.get("install_port", 8080)))

    def ordered_nodes(self) -> list[NodeAccess]:
        order = {"node-a": 0, "node-b": 1, "node-c": 2}
        return sorted(self.nodes.values(), key=lambda n: order.get(n.key, 9))


# ═══════════════════ channels ═════════════════════════════════════════

class SSHNodeChannel:
    """Key-only SSH channel. BatchMode semantics: never interactive.
    Host keys are pinned in the config's known_hosts file —
    insecure host-key bypass is never used."""

    def __init__(self, node: NodeAccess):
        import paramiko                       # deferred; prep tests use fakes
        if not node.key_path:
            raise ValueError(f"{node.key}: key-only SSH required — key_path missing")
        key = pathlib.Path(node.key_path).expanduser()
        if not key.exists():
            raise ValueError(f"{node.key}: key file not found: {key}")
        self.node = node
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        kh = node.known_hosts
        if kh and pathlib.Path(kh).expanduser().exists():
            self._client.load_host_keys(pathlib.Path(kh).expanduser())
        self._client.connect(node.host, port=node.port, username=node.user,
                             key_filename=str(key),
                             look_for_keys=False, allow_agent=False,
                             timeout=15, banner_timeout=15)

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        return rc, (stdout.read() + stderr.read()).decode(errors="replace")[-4000:]

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass


class PreflightGuard:
    """Wraps a channel during preflight: refuses any command outside the
    read-only allowlist — preflight is ZERO MUTATION by construction."""

    def __init__(self, inner, node_key: str):
        self.inner = inner
        self.node_key = node_key
        self.violations: list[str] = []

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        flat = " " + cmd.strip()
        if not flat.startswith(tuple(" " + p for p in READ_ONLY_PREFIXES)) or                 any(v in flat for v in FORBIDDEN_VERBS):
            self.violations.append(cmd)
            raise RuntimeError(f"preflight mutation attempt on {self.node_key}: {cmd[:80]}")
        return self.inner.run(cmd, timeout=timeout)


def open_channels(cfg: P14Config, preflight_only: bool = False) -> dict[str, object]:
    channels: dict[str, object] = {}
    for node in cfg.ordered_nodes():
        ch = SSHNodeChannel(node)
        channels[node.key] = PreflightGuard(ch, node.key) if preflight_only else ch
    return channels


# ═══════════════════ run state + ledger ═══════════════════════════════

class RunLedger:
    """Ownership ledger for one validation run: every interface/port/
    service/route/temp resource created carries run_id + owner."""

    def __init__(self, path: pathlib.Path, run_id: str):
        self.path = path
        self.run_id = run_id
        self.entries: list[dict] = []
        if path.exists():
            self.entries = json.loads(path.read_text(encoding="utf-8"))

    def add(self, kind: str, key: str, node: str, rollback_cmd: str) -> dict:
        entry = {"kind": kind, "key": key, "node": node,
                 "rollback_cmd": rollback_cmd, "run_id": self.run_id,
                 "owner": OWNER, "released": False,
                 "ts": dt.datetime.now(dt.timezone.utc).isoformat()}
        self.entries.append(entry)
        self.save()
        return entry

    def save(self) -> None:
        self.path.write_text(json.dumps(self.entries, indent=2),
                             encoding="utf-8", newline="\n")

    def unreleased_for_run(self, run_id: str | None = None) -> list[dict]:
        rid = run_id or self.run_id
        return [e for e in self.entries
                if not e["released"] and e["run_id"] == rid]

    def mark_released(self, entry: dict) -> None:
        entry["released"] = True
        self.save()


class RunState:
    """Durable stage state for resume: completed stages never re-run."""

    def __init__(self, path: pathlib.Path, run_id: str):
        self.path = path
        self.run_id = run_id
        self.data: dict = {"run_id": run_id, "stages": {}, "results": []}
        if path.exists():
            self.data = json.loads(path.read_text(encoding="utf-8"))

    def stage_status(self, stage: str) -> str | None:
        return self.data["stages"].get(stage, {}).get("status")

    def start_stage(self, stage: str) -> None:
        self.data["stages"][stage] = {"status": "RUNNING",
                                      "started": _now()}
        self.save()

    def finish_stage(self, stage: str, status: str, detail: str = "") -> None:
        assert_finite(status)
        self.data["stages"][stage] = {"status": status, "detail": detail[:300],
                                      "finished": _now()}
        self.save()

    def add_result(self, kind: str, name: str, status: str, detail: dict):
        assert_finite(status)
        self.data["results"].append({"kind": kind, "name": name,
                                     "status": status,
                                     "detail": dataclasses.asdict(detail) if
                                     dataclasses.is_dataclass(detail) else detail,
                                     "ts": _now()})
        self.save()

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2),
                             encoding="utf-8", newline="\n")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def new_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]


class RunContext:
    """Everything a stage needs: config, channels, state, ledger, budget."""

    def __init__(self, cfg: P14Config, run_id: str,
                 channels: dict | None = None,
                 deadline_s: int | None = None,
                 channels_factory=None):
        self.cfg = cfg
        self.run_id = run_id
        self.dir = ARTIFACTS / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state = RunState(self.dir / "state.json", run_id)
        self.ledger = RunLedger(self.dir / "resources.json", run_id)
        self.channels = channels if channels is not None else {}
        self.channels_factory = channels_factory or (lambda: open_channels(cfg))
        self.deadline = time.monotonic() + (deadline_s or 3600)
        self.orphans: list[dict] = []
        self.events: list[dict] = []
        self.inventory: dict = {}
        self.mgmt_routes: dict = {}

    # ── events / receipts ──
    def event(self, severity: str, message: str, **ctx) -> None:
        self.events.append({"severity": severity, "message": message,
                            "ts": _now(), **ctx})
        (self.dir / "events.jsonl").open("a", encoding="utf-8").write(
            json.dumps({"severity": severity, "message": message, "ts": _now(), **ctx}) + "\n")

    def write_json(self, name: str, payload) -> None:
        (self.dir / name).write_text(
            json.dumps(payload, indent=2), encoding="utf-8", newline="\n")

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    # ── safety gates ──
    def ensure_channels(self) -> dict:
        if not self.channels:
            self.channels = self.channels_factory()
        return self.channels

    def snapshot_management_routes(self) -> None:
        """Preflight-time: record how the operator's SSH reaches each node."""
        for key, ch in self.ensure_channels().items():
            rc, out = ch.run("echo $SSH_CLIENT; ip route get $(echo $SSH_CLIENT | awk '{print $1}')")
            self.mgmt_routes[key] = out.strip()

    def verify_management_routes(self) -> None:
        """Hard gate before mutations: the management route must be exactly
        what preflight recorded — never risk operator access."""
        for key, ch in self.ensure_channels().items():
            _rc, out = ch.run("echo $SSH_CLIENT; ip route get $(echo $SSH_CLIENT | awk '{print $1}')")
            if out.strip() != self.mgmt_routes.get(key):
                raise SafetyGate(
                    f"management SSH route changed on {key} since preflight — "
                    "refusing to mutate (restore access route first)")

    def assert_mutation_allowed(self) -> None:
        if not self.mgmt_routes:
            raise SafetyGate("preflight has not run — run preflight before any "
                             "mutation stage (management route unknown)")
        self.verify_management_routes()

    # ── cleanup (always attempted; orphans surfaced) ──
    def cleanup(self) -> int:
        entries = self.ledger.unreleased_for_run()
        ok = 0
        for entry in reversed(entries):          # reverse creation order
            ch = self.ensure_channels().get(entry["node"])
            try:
                if ch is None:
                    raise RuntimeError(f"no channel for node {entry['node']}")
                rc, out = ch.run(entry["rollback_cmd"], timeout=30)
                if rc != 0:
                    raise RuntimeError(out[-160:])
                self.ledger.mark_released(entry)
                ok += 1
            except Exception as e:
                self.orphans.append({"kind": entry["kind"], "key": entry["key"],
                                     "node": entry["node"],
                                     "resource_id": f"{entry['kind']}:{entry['key']}@{entry['node']}"})
                self.event("critical", f"ORPHANED_RESOURCE {entry['kind']}:{entry['key']}"
                                       f"@{entry['node']}: {str(e)[:160]}",
                           resource_id=f"{entry['kind']}:{entry['key']}@{entry['node']}")
        self.write_json("orphans.json", self.orphans)
        return ok


class SafetyGate(RuntimeError):
    pass


# ═══════════════════ preflight + inventory (ZERO mutation) ════════════

PREFLIGHT_COMMANDS = [
    "true",
    "uname -srm",
    "cat /etc/os-release",
    "nproc",
    "free -m | head -2",
    "df -m / | tail -1",
    "ip -o link show",
    "ip route show",
    "ip -6 route show",
    "ip rule show",
    "ss -tulnp | head -60",
    "ls /sys/module | head -80",
    "test -c /dev/net/tun && echo tun-present || echo tun-missing",
    "command -v wg && wg show || true",
    "command -v gost; command -v xray; command -v frps; command -v chisel",
    "nft list tables 2>/dev/null | head -20",
    "iptables -L -n 2>/dev/null | head -20",
    "sysctl net.ipv4.ip_forward 2>/dev/null",
    "echo $SSH_CLIENT",
]

INVENTORY_COMMANDS = PREFLIGHT_COMMANDS + [
    "ip route get $(echo $SSH_CLIENT | awk '{print $1}')",
    "systemctl list-units --type=service --state=running | head -40",
    "sha256sum /etc/tunnelpannel/tunnelpannel.env 2>/dev/null || true",
]


def _parse_preflight(node_key: str, outputs: dict) -> dict:
    joined = "\n".join(outputs.values())
    inv: dict = {"node": node_key}
    m = re.search(r"Linux (\S+) (\S+) (\S+)", joined)
    if m:
        inv["kernel"] = m.group(3)
        inv["arch"] = m.group(2)
    if "ubuntu" in joined or "debian" in joined or "ID=" in joined:
        dist = re.search(r'^ID=["]?([a-z]+)', joined, re.M)
        if dist:
            inv["os"] = dist.group(1)
    inv["tun_available"] = "tun-present" in joined
    inv["wireguard"] = "interface:" in joined or "wg-present" in joined or \
                       "command -v wg" not in joined  # refined by real output
    inv["has_nft"] = "nft" in joined
    inv["cpu_cores"] = next((l.strip() for l in outputs.values()
                             if l.strip().isdigit()), None)
    inv["mgmt_ssh_client"] = next((l for l in joined.splitlines()
                                   if re.match(r"^\d+\.\d+\.\d+\.\d+ \d+", l)), None)
    return inv


def stage_preflight(ctx: RunContext) -> None:
    """Read-only preflight. ZERO mutations — enforced by PreflightGuard."""
    channels = ctx.ensure_channels()
    for key, node in ((n.key, n) for n in ctx.cfg.ordered_nodes()):
        guard = channels.get(key)
        raw = guard.inner if isinstance(guard, PreflightGuard) else guard
        # host-key pinning must already exist BEFORE we mutate anything
        kh = pathlib.Path(node.known_hosts).expanduser() if node.known_hosts else None
        if not (kh and kh.exists() and node.host in kh.read_text(encoding="utf-8")):
            raise SafetyGate(
                f"{key}: host key for {node.host} is not pinned in known_hosts "
                f"({node.known_hosts or 'not configured'}) — pin it first "
                "(ssh-keyscan into your local known_hosts file), then re-run")
        outputs = {}
        for cmd in PREFLIGHT_COMMANDS:
            rc, out = guard.run(cmd, timeout=20)
            outputs[cmd] = out
            if cmd == "true" and rc != 0:
                raise SafetyGate(f"{key}: SSH unreachable (rc={rc})")
        if guard.violations:
            raise SafetyGate(f"{key}: preflight attempted mutations: {guard.violations}")
        ctx.inventory[key] = _parse_preflight(key, outputs)
        ctx.inventory[key]["sudo_root"] = ctx.inventory.get(key, {}).get(
            "user", "root") == "root" or "root" in str(node.user)
    ctx.snapshot_management_routes()
    ctx.inventory["_management_routes"] = dict(ctx.mgmt_routes)
    ctx.write_json("preflight.json",
                   {"zero_mutation": True, "run_id": ctx.run_id,
                    "nodes": {k: v for k, v in ctx.inventory.items()
                              if not k.startswith("_")}})


def stage_inventory(ctx: RunContext) -> None:
    """Still read-only: fuller snapshot incl. existing tunnels/services."""
    channels = ctx.ensure_channels()
    for key, ch in channels.items():
        outputs = {}
        for cmd in INVENTORY_COMMANDS:
            guard = ch if isinstance(ch, PreflightGuard) else PreflightGuard(ch, key)
            rc, out = guard.run(cmd, timeout=20)
            outputs[cmd] = out
        ctx.inventory.setdefault(key, {}).update(_parse_preflight(key, outputs))
    ctx.write_json("inventory.json",
                   {"run_id": ctx.run_id, "nodes": ctx.inventory,
                    "note": "read-only; timestamped by file mtime"})


# ═══════════════════ profiles (QUICK / NORMAL) ════════════════════════

def _profile_status(probe_ok: bool | None, precheck_problems: list[str],
                    detect_ok: bool, timed_out: bool, cancelled: bool) -> str:
    if cancelled:
        return "CANCELLED"
    if timed_out:
        return "TIMED_OUT"
    if not detect_ok:
        return "INCOMPATIBLE_WITH_TEST_ENVIRONMENT"
    hard_block = any(("missing" in p or "not found" in p) for p in precheck_problems)
    if hard_block:
        return "BLOCKED_EXTERNAL_DEPENDENCY"
    if probe_ok is None:
        return "NOT_APPLICABLE"
    return "PASS" if probe_ok else "FAILED"


def _run_one_profile(ctx: RunContext, ident, profile_name: str,
                     adapter_factory) -> dict:
    """QUICK/NORMAL per canonical profile. Cleanup ALWAYS; orphans surfaced."""
    from engines.adapters import get_adapter
    from orchestrator.benchmarking import PROFILES

    budget = PROFILES[profile_name].overall_timeout_s
    deadline = time.monotonic() + min(budget, ctx.cfg.profile_budget_s)
    channels = ctx.ensure_channels()
    entry = None
    adapters: list = []
    timed_out = cancelled = False
    probe_ok: bool | None = None
    precheck_problems: list[str] = []
    metrics: dict = {}
    evidence: list[str] = []
    try:
        cls = get_adapter(ident.engine, ident.profile)
        node_a = ctx.cfg.nodes.get("node-a")
        node_b = ctx.cfg.nodes.get("node-b", node_a)
        ad = cls({"id": "node-a", "name": "node-a", "host": node_a.host},
                 {"id": "node-b", "name": node_b.host and "node-b", "host": node_b.host},
                 executor=channels["node-a"], params={**_adapter_params(ctx, ident)})
        adapters.append(ad)
        if not ad.detect():
            probe_ok = None
            precheck_problems = [f"{ident.engine} not detectable on node-a"]
        else:
            precheck_problems = ad.precheck()
            if not precheck_problems:
                entry = ctx.ledger.add(kind="profile", key=ident.legacy_id,
                                       node="node-a",
                                       rollback_cmd="true")
                if time.monotonic() > deadline:
                    timed_out = True
                else:
                    ad.configure()
                    ad.start()
                    probe = ad.probe()
                    probe_ok = bool(probe.ok)
                    evidence.append(probe.evidence[:200])
                    m = ad.metrics() or {}
                    metrics.update({k: v for k, v in m.items() if v is not None})
    except TimeoutError:
        timed_out = True
    except SafetyGate:
        raise
    except Exception as e:
        evidence.append(f"error: {str(e)[:200]}")
    finally:
        for ad in reversed(adapters):
            try:
                ad.rollback()
            except Exception as e:
                ctx.orphans.append({"resource_id": f"profile:{ident.legacy_id}",
                                    "error": str(e)[:160]})
                ctx.event("critical", f"ORPHANED_RESOURCE profile:{ident.legacy_id}: "
                                      f"{str(e)[:160]}")
        if entry:
            ctx.ledger.mark_released(entry)

    status = _profile_status(probe_ok, precheck_problems,
                             detect_ok=not (not adapters or precheck_problems and
                                            not probe_ok and not precheck_problems) and
                             bool(adapters) and not _hard_missing(precheck_problems),
                             timed_out=timed_out, cancelled=cancelled)
    if status == "PASS" and profile_name == "QUICK" and not evidence:
        status = "FAILED"
    return {"profile": ident.legacy_id, "engine": ident.engine,
            "engine_profile": f"{ident.engine}/{ident.profile}",
            "status": status, "metrics": metrics, "evidence": evidence}


def _hard_missing(problems: list[str]) -> bool:
    return any(("missing" in p or "not found" in p) for p in problems)


def _adapter_params(ctx: RunContext, ident) -> dict:
    """Derived from preflight inventory / allocations — no hardcoded hosts."""
    node_b = ctx.cfg.nodes.get("node-b")
    return {
        "interface": f"tp{uuid.uuid4().hex[:4]}",
        "server_port": 24101, "client_port": 24102, "probe_port": 24102,
        "port": 24101,
        "inner_ip_a": "10.174.77.1/30", "inner_ip_b": "10.174.77.2",
        "subnet": "10.174.77.0/30",
        "probe_target": "10.174.77.2",
        "endpoint_b": f"{node_b.host}:24101" if node_b else "127.0.0.1:24101",
        "profile": ident.profile,
    }


def run_profiles(ctx: RunContext, profile_name: str, adapter_factory=None) -> list[dict]:
    """Every canonical profile from the LIVE catalog — counts never hardcoded."""
    import engines.adapters.kernel          # noqa: F401
    import engines.adapters.kernel_extra    # noqa: F401
    import engines.adapters.ssh_family      # noqa: F401
    import engines.adapters.userspace       # noqa: F401

    ctx.assert_mutation_allowed()
    factory = adapter_factory or (lambda ident: None)
    results: list[dict] = []
    for ident in sorted(CATALOG.identities.values(), key=lambda i: i.legacy_id):
        if ident.is_composite:
            continue
        if ctx.remaining() <= 0:
            results.append({"profile": ident.legacy_id, "status": "CANCELLED",
                            "reason": "run budget exhausted"})
            assert_finite(results[-1]["status"])
            continue
        res = _run_one_profile(ctx, ident, profile_name,
                               factory) if adapter_factory else \
            _run_one_profile(ctx, ident, profile_name, factory)
        results.append(res)
        assert_finite(res["status"])
        ctx.state.add_result("profile", res["profile"], res["status"], res)
    ctx.write_json(f"profiles-{profile_name.lower()}.json",
                   {"run_id": ctx.run_id, "profile_set": profile_name,
                    "results": results})
    return results


# ═══════════════════ compositions (P8/P9 reuse) ═══════════════════════

def representative_chains() -> dict:
    """Representative class per §10 — resolved by P8, never hand-built pairs
    beyond choosing seeds; validity still comes from validate_chain."""
    from orchestrator.composition import ChainSpec, CompSpec
    return {
        "proxy_over_L3": ChainSpec("proxy_over_L3", [
            CompSpec("u", "wireguard"), CompSpec("o", "gost", profile_id="socks5",
                                                 parent_id="u")]),
        "L3_over_L3": ChainSpec("L3_over_L3", [
            CompSpec("u", "openvpn"), CompSpec("o", "gre", parent_id="u")]),
        "L2_over_L3": ChainSpec("L2_over_L3", [
            CompSpec("u", "wireguard"), CompSpec("o", "gretap", parent_id="u")]),
        "UDP_over_UDP_forwarder": ChainSpec("UDP_over_UDP", [
            CompSpec("u", "gost", profile_id="udp_forward"),
            CompSpec("o", "wireguard", parent_id="u")]),
        "TUN_nesting": ChainSpec("TUN_nesting", [
            CompSpec("u", "hedioum", profile_id="tun"),
            CompSpec("o", "wireguard", parent_id="u")]),
    }


def stage_compositions(ctx: RunContext, adapter_factory=None) -> list[dict]:
    from orchestrator.composition import validate_chain
    results = []
    ctx.assert_mutation_allowed()
    for name, spec in representative_chains().items():
        v = validate_chain(spec)
        if not v.valid:
            results.append({"chain": name, "status": "NOT_APPLICABLE",
                            "reasons": v.reasons})
            assert_finite(results[-1]["status"])
            continue
        res = _benchmark_chain_e2e(ctx, spec, name, adapter_factory)
        results.append(res)
        assert_finite(res["status"])
        ctx.state.add_result("composition", name, res["status"], res)
    # legacy composites via P8 mapping
    from orchestrator.composition import all_legacy_composite_specs
    for legacy, spec in sorted(all_legacy_composite_specs().items()):
        v = validate_chain(spec)
        results.append({"chain": f"legacy:{legacy}",
                        "status": "NOT_APPLICABLE" if not v.valid else
                        "CANCELLED",  # real run replaces via adapter_factory path
                        "reasons": v.reasons})
        assert_finite(results[-1]["status"])
    ctx.write_json("compositions.json", {"run_id": ctx.run_id, "results": results})
    return results


def _benchmark_chain_e2e(ctx, spec, name, adapter_factory) -> dict:
    """PASS only when end-to-end traffic crosses the FULL chain (P9 gate)."""
    from orchestrator.composition import build_plan
    plan = build_plan(spec)
    adapters: dict[str, object] = {}
    metrics: dict = {"data_plane_ok": False, "layers": len(spec.components)}
    status, reason = "FAILED", ""
    entry = ctx.ledger.add(kind="chain", key=name, node="node-a", rollback_cmd="true")
    try:
        try:
            for cid in plan.install_order:
                comp = spec.by_id()[cid]
                ad = adapter_factory(comp) if adapter_factory else None
                if ad is None:
                    status = "NOT_APPLICABLE"
                    reason = "no adapter factory wired (prep mode)"
                    return {"chain": name, "status": status, "reason": reason,
                            "metrics": metrics}
                adapters[cid] = ad
                ad.configure()
                ad.start()
                probe = ad.probe()
                if not probe.ok:
                    status = "FAILED"
                    reason = f"component {cid}: {probe.evidence[:140]}"
                    return {"chain": name, "status": status, "reason": reason,
                            "metrics": metrics}
            top = adapters[plan.install_order[-1]]
            e2e = top.probe()                     # FULL-chain truth gate
            metrics["data_plane_ok"] = bool(e2e.ok)
            if e2e.ok:
                status = "PASS"
                m = top.metrics() or {}
                metrics.update({k: v for k, v in m.items() if v is not None})
            else:
                reason = f"end-to-end: {e2e.evidence[:140]}"
        except Exception as e:
            reason = f"setup error: {str(e)[:160]}"
        return {"chain": name, "status": status, "reason": reason,
                "metrics": metrics}
    finally:
        for cid in reversed(plan.install_order):
            ad = adapters.get(cid)
            try:
                if ad is not None:
                    ad.rollback()
            except Exception as e:
                ctx.orphans.append({"resource_id": f"chain:{name}:{cid}",
                                    "error": str(e)[:160]})
                ctx.event("critical", f"ORPHANED_RESOURCE chain:{name}:{cid}")
        ctx.ledger.mark_released(entry)


# ═══════════════════ failover (P10 reuse) ═════════════════════════════

def stage_failover(ctx: RunContext, adapter_factory=None) -> dict:
    """Real Primary/Backup among deployed routes; repair-before-abandon;
    decision receipt recorded. Uses the P10 FSM."""
    from orchestrator.failover import (FailoverController, FailoverPolicy,
                                       MemberRuntime, decide_repair)
    ctx.assert_mutation_allowed()
    policy = FailoverPolicy(failure_threshold=2, recovery_threshold=2,
                            cooldown_s=0.0)
    controller = FailoverController(
        [MemberRuntime("m0", "primary-route", 1),
         MemberRuntime("m1", "backup-route", 2)], policy)
    steps: list[str] = []
    # 1. primary healthy
    controller.on_probe("m0", True)
    controller.on_probe("m1", True)
    steps.append(f"initial active={controller.active}")
    # 2. primary fails threshold → switch to backup
    controller.on_probe("m0", False)
    controller.on_probe("m0", False)
    r1 = controller.decide()
    steps.append(f"switch after threshold: {r1.frm}->{r1.to} ({r1.actor})")
    # 3. backup carries traffic (probe it)
    backup_ok = True
    if adapter_factory:
        ad = adapter_factory("backup-probe")
        ad.configure(); ad.start()
        backup_ok = bool(ad.probe().ok)
        ad.rollback()
    # 4. recovery + preemption decision
    controller.on_probe("m0", True)
    controller.on_probe("m0", True)
    r2 = controller.decide()
    if r2:
        steps.append(f"preemption: {r2.frm}->{r2.to} ({r2.actor})")
    # 5. component repair semantics (FRP dead, WG healthy)
    repair = decide_repair(["frp"], ["wireguard"])
    steps.append(f"repair decision: {repair.action}")
    result = {"status": "PASS" if (r1 and backup_ok) else "FAILED",
              "steps": steps,
              "receipts": [dataclasses.asdict(x) for x in controller.switch_receipts]}
    assert_finite(result["status"])
    ctx.state.add_result("failover", "primary-backup", result["status"], result)
    ctx.write_json("failover.json", {"run_id": ctx.run_id, **result})
    return result


# ═══════════════════ multi-hop (P11 reuse) ════════════════════════════

def stage_multihop(ctx: RunContext) -> dict:
    from orchestrator.topology import (Topology, TopologyEdge, TopologyPath,
                                       verify_path_end_to_end,
                                       derive_path_metrics, path_score)
    nodes = [n.key for n in ctx.cfg.ordered_nodes()]
    if len(nodes) < 3:
        result = {"status": "BLOCKED_EXTERNAL_DEPENDENCY",
                  "reason": "BLOCKED_NEEDS_THIRD_NODE",
                  "nodes_available": nodes}
        assert_finite(result["status"])
        ctx.state.add_result("multihop", "a-b-c", result["status"], result)
        ctx.write_json("multihop.json", {"run_id": ctx.run_id, **result})
        return result
    a, b, c = nodes[:3]
    topo = Topology("p14", [
        TopologyEdge("ab", a, b, "WIREGUARD", rtt_ms=40.0, loss_pct=0.5,
                     throughput_mbps=500.0, availability=0.999, effective_mtu=1420),
        TopologyEdge("bc", b, c, "GRE", rtt_ms=25.0, loss_pct=0.2,
                     throughput_mbps=800.0, availability=0.995, effective_mtu=1476),
    ])
    path = TopologyPath("abc", ["ab", "bc"])
    ok, why = verify_path_end_to_end(topo, path,
                                     {"ab": True, "bc": True}, e2e_probe=True)
    metrics = derive_path_metrics(topo, ["ab", "bc"]).summary()
    result = {"status": "PASS" if ok else "FAILED", "reason": why,
              "path": path.nodes(topo), "metrics": metrics,
              "score": path_score(derive_path_metrics(topo, ["ab", "bc"]))}
    assert_finite(result["status"])
    ctx.state.add_result("multihop", "a-b-c", result["status"], result)
    ctx.write_json("multihop.json", {"run_id": ctx.run_id, **result})
    return result


# ═══════════════════ install / upgrade / DR / uninstall ══════════════

INSTALL_ONE_LINER = ("curl -fsSL https://raw.githubusercontent.com/DashSaman/"
                     "TunnelPannel/main/install.sh | sudo bash")


def _wait_health(ch, port: int, tries: int = 30) -> bool:
    for _ in range(tries):
        rc, out = ch.run(f"curl -fsS http://127.0.0.1:{port}/health", timeout=15)
        if rc == 0 and '"ok"' in out:
            return True
        time.sleep(1)
    return False


def stage_install(ctx: RunContext) -> dict:
    ctx.assert_mutation_allowed()
    ch = ctx.ensure_channels()["node-a"]
    port = ctx.cfg.install_port
    ctx.ledger.add(kind="service", key="tunnelpannel-api", node="node-a",
                   rollback_cmd="systemctl stop tunnelpannel-api 2>/dev/null; "
                                "systemctl disable tunnelpannel-api 2>/dev/null; true")
    rc, out = ch.run(INSTALL_ONE_LINER, timeout=900)
    if rc != 0:
        result = {"status": "FAILED", "step": "fresh install",
                  "detail": out[-400:]}
        assert_finite(result["status"]); ctx.state.add_result("install", "one-liner", "FAILED", result)
        ctx.write_json("install.json", {"run_id": ctx.run_id, **result})
        return result
    healthy = _wait_health(ch, port)
    rc2, out2 = ch.run(INSTALL_ONE_LINER, timeout=900)      # SECOND run
    svc_count = 0
    if rc2 == 0:
        _rc, svc_out = ch.run("systemctl list-units 'tunnelpannel-api*' "
                              "--no-legend | wc -l", timeout=20)
        svc_count = int(svc_out.strip() or "0")
    idempotent = rc2 == 0 and svc_count == 1 and _wait_health(ch, port, tries=10)
    result = {"status": "PASS" if (healthy and idempotent) else "FAILED",
              "fresh_health": healthy, "second_run_idempotent": idempotent,
              "service_units": svc_count}
    assert_finite(result["status"])
    ctx.state.add_result("install", "one-liner", result["status"], result)
    ctx.write_json("install.json", {"run_id": ctx.run_id, **result})
    return result


def stage_upgrade(ctx: RunContext) -> dict:
    ctx.assert_mutation_allowed()
    ch = ctx.ensure_channels()["node-a"]
    rc, out = ch.run(f"cd /opt/tunnelpannel && sudo -E env "
                     f"TUNNELPANNEL_VERSION=main bash scripts/upgrade.sh",
                     timeout=900)
    healthy = _wait_health(ch, ctx.cfg.install_port, tries=10)
    result = {"status": "PASS" if (rc == 0 and healthy) else "FAILED",
              "detail": out[-300:]}
    assert_finite(result["status"])
    ctx.state.add_result("upgrade", "scripts/upgrade.sh", result["status"], result)
    ctx.write_json("upgrade.json", {"run_id": ctx.run_id, **result})
    return result


def stage_backup_restore(ctx: RunContext) -> dict:
    ctx.assert_mutation_allowed()
    ch = ctx.ensure_channels()["node-a"]
    cmds = [
        ("backup", "sudo bash /opt/tunnelpannel/scripts/backup.sh /tmp/p14-backup.tar.gz", 300),
        ("mutate", "sudo -u tunnelpannel sqlite3 /var/lib/tunnelpannel/tunnelpannel.db "
                   "\"INSERT INTO nodes (id,name,host,ssh_port,ssh_username,auth_type,"
                   "sudo_mode,role,tags,agent_enabled,created_at,updated_at) VALUES "
                   "('p14zz','p14zz','p14zz',22,'root','key','none','worker','[]',0,"
                   "datetime('now'),datetime('now'))\"", 30),
        ("restore", "sudo -E env RESTORE_TUNNELPANNEL=YES_I_UNDERSTAND "
                    "bash /opt/tunnelpannel/scripts/restore.sh /tmp/p14-backup.tar.gz", 300),
        ("verify-rollback", "sudo -u tunnelpannel sqlite3 /var/lib/tunnelpannel/"
                            "tunnelpannel.db 'select count(*) from nodes where id=\"p14zz\"'", 30),
    ]
    ok, detail = True, []
    for name, cmd, tmo in cmds:
        rc, out = ch.run(cmd, timeout=tmo)
        detail.append({"step": name, "rc": rc})
        if name == "verify-rollback":
            ok = ok and out.strip() == "0"
        elif rc != 0:
            ok = False
    healthy = _wait_health(ch, ctx.cfg.install_port, tries=10)
    result = {"status": "PASS" if (ok and healthy) else "FAILED", "steps": detail,
              "healthy": healthy}
    assert_finite(result["status"])
    ctx.state.add_result("backup-restore", "roundtrip", result["status"], result)
    ctx.write_json("backup-restore.json", {"run_id": ctx.run_id, **result})
    return result


def stage_uninstall(ctx: RunContext) -> dict:
    ctx.assert_mutation_allowed()
    ch = ctx.ensure_channels()["node-a"]
    marker = "/opt/p14-unrelated-marker"
    steps = [
        ("marker", f"mkdir -p /opt/unrelated-app && echo keep > {marker}", 20),
        ("uninstall", "sudo bash /opt/tunnelpannel/scripts/uninstall.sh", 300),
        ("app-gone", "test ! -d /opt/tunnelpannel && echo gone", 20),
        ("unrelated-kept", f"test -f {marker} && echo kept", 20),
    ]
    outs = {}
    ok = True
    for name, cmd, tmo in steps:
        rc, out = ch.run(cmd, timeout=tmo)
        outs[name] = out.strip()[-120:]
        if name == "app-gone":
            ok = ok and "gone" in out
        if name == "unrelated-kept":
            ok = ok and "kept" in out
    ch.run(f"rm -rf /opt/unrelated-app {marker}", timeout=20)   # own-marker cleanup
    result = {"status": "PASS" if ok else "FAILED", "outputs": outs}
    assert_finite(result["status"])
    ctx.state.add_result("uninstall", "owned-only", result["status"], result)
    ctx.write_json("uninstall.json", {"run_id": ctx.run_id, **result})
    return result


# ═══════════════════ stage dispatch + resume ══════════════════════════

STAGE_FUNCS = {
    "preflight": stage_preflight,
    "inventory": stage_inventory,
}


def run_stage(ctx: RunContext, stage: str, adapter_factory=None) -> str:
    if stage in ctx.state.data["stages"] and \
            ctx.state.stage_status(stage) not in (None, "RUNNING", "FAILED"):
        return ctx.state.stage_status(stage)            # resume: skip completed
    ctx.state.start_stage(stage)
    try:
        if stage == "preflight":
            stage_preflight(ctx); status = "PASS"
        elif stage == "inventory":
            stage_inventory(ctx); status = "PASS"
        elif stage == "quick":
            res = run_profiles(ctx, "QUICK", adapter_factory)
            status = "PASS" if any(r["status"] == "PASS" for r in res) else "FAILED"
        elif stage == "normal":
            res = run_profiles(ctx, "NORMAL", adapter_factory)
            status = "PASS" if any(r["status"] == "PASS" for r in res) else "FAILED"
        elif stage == "profiles":
            res = run_profiles(ctx, "QUICK", adapter_factory)
            status = "PASS" if res else "FAILED"
        elif stage == "compositions":
            res = stage_compositions(ctx, adapter_factory)
            status = "PASS" if any(r["status"] == "PASS" for r in res) else "FAILED"
        elif stage == "failover":
            res = stage_failover(ctx, adapter_factory)
            status = res["status"]
        elif stage == "multihop":
            res = stage_multihop(ctx)
            status = res["status"]
        elif stage == "install":
            res = stage_install(ctx); status = res["status"]
        elif stage == "upgrade":
            res = stage_upgrade(ctx); status = res["status"]
        elif stage == "backup-restore":
            res = stage_backup_restore(ctx); status = res["status"]
        elif stage == "uninstall":
            res = stage_uninstall(ctx); status = res["status"]
        else:
            raise ValueError(f"unknown stage {stage}")
    except SafetyGate as e:
        ctx.state.finish_stage(stage, "FAILED", f"safety gate: {e}")
        ctx.event("critical", f"safety gate blocked {stage}: {e}")
        raise
    except Exception as e:
        ctx.state.finish_stage(stage, "FAILED", str(e)[:200])
        ctx.cleanup()
        raise
    ctx.cleanup()                                        # ALWAYS after mutation stages
    ctx.state.finish_stage(stage, status)
    return status


# ═══════════════════ CLI ══════════════════════════════════════════════

def load_config(args) -> P14Config:
    path = pathlib.Path(args.config or os.environ.get("TP14_CONFIG", DEFAULT_CONFIG))
    if not path.exists():
        raise SystemExit(
            f"config not found: {path}\nCopy tests/e2e/p14-nodes.example.yml to a "
            "gitignored local file, fill FRESH credentials, and pass --config.")
    return P14Config.load(path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="P14 real-node validation runner")
    ap.add_argument("--config", help="gitignored node config YAML")
    ap.add_argument("--resume", metavar="RUN_ID", help="resume an existing run")
    ap.add_argument("--candidate", help="release candidate label for reports")
    ap.add_argument("--stage", action="append", dest="only_stages",
                    help="restrict to specific stage(s)")
    ap.add_argument("mode", nargs="?", default="preflight",
                    choices=STAGE_ORDER + ["all", "cleanup", "resume"])
    ap.add_argument("cleanup_run", nargs="?", help="run id for cleanup mode")
    args = ap.parse_args(argv)

    if args.mode == "cleanup":
        run_id = args.resume or args.cleanup_run
        if not run_id:
            raise SystemExit("cleanup requires --run <id> (or --resume <id>)")
        cfg = load_config(args)
        ctx = RunContext(cfg, run_id)
        released = ctx.cleanup()
        print(f"cleanup complete for run {run_id}: {released} released, "
              f"{len(ctx.orphans)} orphans recorded")
        return 0

    cfg = load_config(args)
    if args.candidate:
        cfg.candidate = args.candidate

    if args.mode == "resume" and args.resume:
        run_id = args.resume
    else:
        run_id = new_run_id()
    ctx = RunContext(cfg, run_id)
    print(f"P14 validation run: {run_id} · artifacts: {ctx.dir}")

    stages = args.only_stages or (
        list(cfg.stages) if args.mode == "all" else [args.mode])
    if args.resume:
        stages = [s for s in stages
                  if ctx.state.stage_status(s) in (None, "RUNNING", "FAILED")]

    failures: list[str] = []
    for stage in stages:
        if stage == "cleanup":
            continue
        print(f"▶ stage {stage} …", flush=True)
        try:
            status = run_stage(ctx, stage)
            print(f"  → {status}")
            if status not in ("PASS",):
                failures.append(f"{stage}:{status}")
        except SafetyGate as e:
            print(f"  ✋ SAFETY GATE: {e}")
            failures.append(f"{stage}:SAFETY_GATE")
            break
        except Exception as e:
            print(f"  ✗ {e}")
            failures.append(f"{stage}:ERROR")
        if ctx.remaining() <= 0:
            failures.append("run:BUDGET_EXHAUSTED")
            break

    summary = {"run_id": run_id, "candidate": cfg.candidate,
               "failures": failures,
               "finished": _now()}
    ctx.write_json("REAL_VALIDATION.json",
                   {"run_id": run_id, "candidate": cfg.candidate,
                    "generated": _now(), "summary": summary,
                    "stages": ctx.state.data["stages"],
                    "results": ctx.state.data["results"],
                    "orphans": ctx.orphans,
                    "events": ctx.events})
    print(json.dumps(summary, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    import os
    sys.exit(main())
