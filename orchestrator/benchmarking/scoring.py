"""Scoring + ranking (P6 §28-§31).

Explicit normalization functions with documented boundary behavior; the
agreed default weights; hard failure gates that no average can hide; and
a deterministic, documented ranking order.
"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_WEIGHTS = {
    "availability": 20,      # data-plane success
    "loss": 18,
    "latency": 15,
    "jitter": 12,
    "stability": 10,
    "throughput": 10,
    "recovery": 7,
    "resource_efficiency": 5,
    "deployment_reliability": 3,
}                                # total = 100 (asserted in tests)


def assert_weights(w: dict) -> None:
    total = sum(w.values())
    if total != 100:
        raise ValueError(f"scoring weights must total 100, got {total}")


# ── normalization functions (0..100) ──────────────────────────────────
# Boundary behavior: worse-than-worst input clamps to 0; better-than-best
# clamps to 100. None metrics score neutral 0 weight via *_present flags.

def latency_score(rtt_avg_ms: float | None, best_ms: float = 5.0, worst_ms: float = 800.0) -> float | None:
    if rtt_avg_ms is None:
        return None
    if rtt_avg_ms <= best_ms:
        return 100.0
    if rtt_avg_ms >= worst_ms:
        return 0.0
    return 100.0 * (worst_ms - rtt_avg_ms) / (worst_ms - best_ms)


def loss_score(loss_pct: float | None, ok_pct: float = 0.0, worst_pct: float = 20.0) -> float | None:
    if loss_pct is None:
        return None
    if loss_pct <= ok_pct:
        return 100.0
    if loss_pct >= worst_pct:
        return 0.0
    return 100.0 * (worst_pct - loss_pct) / (worst_pct - ok_pct)


def jitter_score(jitter_ms: float | None, best_ms: float = 0.5, worst_ms: float = 100.0) -> float | None:
    if jitter_ms is None:
        return None
    if jitter_ms <= best_ms:
        return 100.0
    if jitter_ms >= worst_ms:
        return 0.0
    return 100.0 * (worst_ms - jitter_ms) / (worst_ms - best_ms)


def throughput_score(mbps: float | None, floor_mbps: float = 10.0, ceil_mbps: float = 1000.0) -> float | None:
    if mbps is None:
        return None
    if mbps <= floor_mbps:
        return 0.0
    if mbps >= ceil_mbps:
        return 100.0
    return 100.0 * (mbps - floor_mbps) / (ceil_mbps - floor_mbps)


def recovery_score(reconnect_s: float | None, best_s: float = 1.0, worst_s: float = 60.0) -> float | None:
    if reconnect_s is None:
        return None
    if reconnect_s <= best_s:
        return 100.0
    if reconnect_s >= worst_s:
        return 0.0
    return 100.0 * (worst_s - reconnect_s) / (worst_s - best_s)


def resource_score(cpu_pct: float | None, ram_mb: float | None) -> float | None:
    if cpu_pct is None and ram_mb is None:
        return None
    cpu = 100.0 - min(max(cpu_pct or 0.0, 0.0), 100.0)
    ram = 100.0 * (1.0 - min(max((ram_mb or 0) / 512.0, 0.0), 1.0))
    return 0.5 * cpu + 0.5 * ram


def stability_score(uptime_ratio: float | None) -> float | None:
    if uptime_ratio is None:
        return None
    return 100.0 * min(max(uptime_ratio, 0.0), 1.0)


# ── hard gates + score assembly ───────────────────────────────────────

@dataclass
class ScoredSample:
    candidate: str
    status: str                       # PASS|DEGRADED|FAILED|BLOCKED|INCOMPATIBLE|TIMED_OUT|CANCELLED
    score: float | None               # None for BLOCKED/INCOMPATIBLE — no fake low score
    reasons: list[str]
    metrics: dict


def score_sample(candidate: str, metrics: dict, status: str,
                 weights: dict | None = None) -> ScoredSample:
    w = dict(weights or DEFAULT_WEIGHTS)
    assert_weights(w)

    reasons: list[str] = []

    # hard gates (§30): no averaging can rescue these; TIMED_OUT/CANCELLED
    # carry no performance verdict (None score), like BLOCKED/INCOMPATIBLE
    if status in ("BLOCKED", "INCOMPATIBLE", "CANCELLED", "TIMED_OUT"):
        return ScoredSample(candidate, status, None,
                            [metrics.get("reason", status)], metrics)
    data_plane_ok = bool(metrics.get("data_plane_ok"))
    if status == "FAILED" or not data_plane_ok:
        why = metrics.get("reason") or "hard gate: real data-plane failed"
        return ScoredSample(candidate, "FAILED", 0.0, [why], metrics)

    parts: list[tuple[str, float, float]] = []
    lat = latency_score(metrics.get("rtt_avg"))
    if lat is not None:
        parts.append(("latency", lat, w["latency"]))
        reasons.append(f"rtt_avg {metrics.get('rtt_avg'):.0f} ms" if metrics.get("rtt_avg") else "rtt n/a")
    ls = loss_score(metrics.get("loss_pct"))
    if ls is not None:
        parts.append(("loss", ls, w["loss"]))
        reasons.append(f"loss {metrics.get('loss_pct'):.1f}%")
    js = jitter_score(metrics.get("jitter"))
    if js is not None:
        parts.append(("jitter", js, w["jitter"]))
        reasons.append(f"jitter {metrics.get('jitter'):.1f} ms")
    ts = throughput_score(metrics.get("throughput_mbps"))
    if ts is not None:
        parts.append(("throughput", ts, w["throughput"]))
    ss = stability_score(metrics.get("stability_ratio"))
    if ss is not None:
        parts.append(("stability", ss, w["stability"]))
    rs = recovery_score(metrics.get("reconnect_s"))
    if rs is not None:
        parts.append(("recovery", rs, w["recovery"]))
    res = resource_score(metrics.get("cpu_pct"), metrics.get("ram_mb"))
    if res is not None:
        parts.append(("resource_efficiency", res, w["resource_efficiency"]))

    # availability: data-plane succeeded (hard gate already ensured)
    parts.append(("availability", 100.0, w["availability"]))

    # deployment reliability: full marks when setup succeeded in this run
    parts.append(("deployment_reliability",
                  100.0 if metrics.get("setup_ok") else 0.0, w["deployment_reliability"]))

    total_w = sum(wt for _n, _s, wt in parts)
    raw = sum(s * wt for _n, s, wt in parts) / total_w if total_w else 0.0

    final_status = "PASS"
    degraded = (ls is not None and ls < 60) or (js is not None and js < 50) or \
               (lat is not None and lat < 40)
    if degraded:
        final_status = "DEGRADED"
        reasons.append("degraded thresholds tripped")
    return ScoredSample(candidate, final_status, round(raw, 2), reasons, metrics)


# ── deterministic ranking (§31) ───────────────────────────────────────
# Documented order: score desc → loss asc → p95 asc → jitter asc →
# stability desc → candidate id asc (stable final tie-break).

RANK_LEAGUES = ("PASS", "DEGRADED", "FAILED", "TIMED_OUT", "BLOCKED", "INCOMPATIBLE")


def rank(samples: list[ScoredSample]) -> list[ScoredSample]:
    def key(s: ScoredSample):
        m = s.metrics
        return (
            RANK_LEAGUES.index(s.status) if s.status in RANK_LEAGUES else 99,
            -(s.score if s.score is not None else -1.0),
            m.get("loss_pct") if m.get("loss_pct") is not None else 1e9,
            m.get("rtt_p95") if m.get("rtt_p95") is not None else 1e9,
            m.get("jitter") if m.get("jitter") is not None else 1e9,
            -(m.get("stability_ratio") or 0.0),
            s.candidate,                      # deterministic final tie-break
        )
    return sorted(samples, key=key)
