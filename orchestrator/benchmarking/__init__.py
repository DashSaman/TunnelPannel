"""Benchmark engine core (P6): compatibility, profiles, statistics.

§17-§25: candidate resolution from node capabilities, bounded profiles,
honest statistics (p99 only with enough samples — never fabricated).
"""
from __future__ import annotations

import dataclasses
import math
import statistics
from dataclasses import dataclass

from core.catalog import CATALOG
from engines.manifests import load_all

P99_MIN_SAMPLES = 100               # below this, p99 is NOT_AVAILABLE


# ── compatibility resolution ──────────────────────────────────────────

@dataclass
class NodeCaps:
    """Distilled node capability snapshot (from P5 inventories)."""
    node_id: str
    os: str = "linux"
    arch: str = "amd64"
    binaries: set[str] = dataclasses.field(default_factory=set)
    kernel_modules: set[str] = dataclasses.field(default_factory=set)
    privileged: bool = True          # CAP_NET_ADMIN available
    tun_tap: bool = True


@dataclass
class Candidate:
    engine: str
    profile: str
    legacy_method_id: str
    family: str
    status: str                      # COMPATIBLE | INCOMPATIBLE | BLOCKED
    reason: str = ""


def resolve_candidates(a: NodeCaps, b: NodeCaps,
                       catalog=None, manifests=None) -> list[Candidate]:
    """Every standalone method with an honest compatibility verdict."""
    catalog = catalog or CATALOG
    manifests = manifests or load_all()
    out: list[Candidate] = []
    for ident in catalog.identities.values():
        if ident.is_composite:
            continue                                  # P8 territory
        m = manifests.get(ident.engine)
        if m is None:
            out.append(Candidate(ident.engine, ident.profile, ident.legacy_id,
                                  ident.family, "INCOMPATIBLE", "no manifest"))
            continue
        blockers: list[str] = []
        for node in (a, b):
            if node.os not in m["supported_os"]:
                blockers.append(f"{node.node_id}: os {node.os} unsupported")
            if node.arch not in m["supported_arch"]:
                blockers.append(f"{node.node_id}: arch {node.arch} unsupported")
            need_priv = str(m.get("required_privileges", "")).startswith("CAP_NET_ADMIN")
            if need_priv and not node.privileged:
                blockers.append(f"{node.node_id}: CAP_NET_ADMIN unavailable")
            if m.get("layer") in ("L2", "L3") and not node.privileged:
                blockers.append(f"{node.node_id}: L2/L3 engine needs privileges")
            missing_bins = [b for b in m["required_binaries"] if b not in node.binaries]
            if missing_bins:
                blockers.append(f"{node.node_id}: missing binaries {missing_bins}")
            missing_mods = [k for k in m["required_kernel_modules"] if k not in node.kernel_modules]
            # missing module is BLOCKED (installable), not INCOMPATIBLE
        hard = [x for x in blockers if "unsupported" in x or "CAP_NET_ADMIN" in x or "privileges" in x]
        soft = [x for x in blockers if x not in hard]
        if hard:
            out.append(Candidate(ident.engine, ident.profile, ident.legacy_id,
                                 ident.family, "INCOMPATIBLE", "; ".join(hard)))
        elif soft:
            out.append(Candidate(ident.engine, ident.profile, ident.legacy_id,
                                 ident.family, "BLOCKED", "; ".join(soft)))
        else:
            out.append(Candidate(ident.engine, ident.profile, ident.legacy_id,
                                 ident.family, "COMPATIBLE"))
    return out


# ── profiles (finite budgets — §21-§23) ───────────────────────────────

@dataclass(frozen=True)
class BenchProfile:
    name: str
    rtt_probes: int
    throughput_seconds: int          # 0 = skip
    restart_test: bool
    setup_timeout_s: int
    probe_timeout_s: int
    throughput_timeout_s: int
    teardown_timeout_s: int
    overall_timeout_s: int

    @property
    def methodology(self) -> dict:
        return dataclasses.asdict(self)


PROFILES: dict[str, BenchProfile] = {
    "QUICK": BenchProfile("QUICK", rtt_probes=5, throughput_seconds=0,
                          restart_test=False, setup_timeout_s=60, probe_timeout_s=10,
                          throughput_timeout_s=0, teardown_timeout_s=30,
                          overall_timeout_s=180),
    "NORMAL": BenchProfile("NORMAL", rtt_probes=30, throughput_seconds=10,
                           restart_test=True, setup_timeout_s=120, probe_timeout_s=15,
                           throughput_timeout_s=30, teardown_timeout_s=45,
                           overall_timeout_s=600),
    "DEEP": BenchProfile("DEEP", rtt_probes=100, throughput_seconds=60,
                         restart_test=True, setup_timeout_s=180, probe_timeout_s=20,
                         throughput_timeout_s=120, teardown_timeout_s=60,
                         overall_timeout_s=1800),
}

DEFAULT_MAX_PARALLEL = 2


# ── honest statistics (§24) ───────────────────────────────────────────

def rtt_stats(samples_ms: list[float]) -> dict:
    """min/avg/p50/p95/p99 — p99 only with >= P99_MIN_SAMPLES samples."""
    if not samples_ms:
        return {"rtt_min": None, "rtt_avg": None, "rtt_p50": None,
                "rtt_p95": None, "rtt_p99": None, "jitter": None, "samples": 0}
    xs = sorted(samples_ms)
    n = len(xs)

    def pct(p: float) -> float:
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return xs[int(k)]
        return xs[f] + (xs[c] - xs[f]) * (k - f)

    diffs = [abs(b - a) for a, b in zip(xs, xs[1:])] if n >= 2 else [0.0]
    return {
        "rtt_min": xs[0],
        "rtt_avg": statistics.fmean(xs),
        "rtt_p50": pct(0.50),
        "rtt_p95": pct(0.95),
        "rtt_p99": pct(0.99) if n >= P99_MIN_SAMPLES else None,   # honest
        "jitter": statistics.fmean(diffs),
        "samples": n,
    }


def loss_pct(probes_sent: int, probes_failed: int) -> float | None:
    if probes_sent <= 0:
        return None
    return 100.0 * probes_failed / probes_sent
