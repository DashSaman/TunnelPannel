"""Observability (P12 §14-§17): lightweight health sampling, rollups with
retention, stability history, optional Prometheus export.

Monitoring NEVER depends on heavy benchmark jobs — probes are cheap;
iperf/deep tests stay on-demand or scheduled-maintenance only.
"""
from __future__ import annotations

import datetime as dt
import statistics
from dataclasses import dataclass

from sqlalchemy.orm import Session

from core.models import HealthSample


# ── health sampling (§15) ──────────────────────────────────────────────

@dataclass
class ProbePolicy:
    interval_s: int = 30                  # lightweight periodic probe
    rtt_timeout_s: int = 5
    heavy_tests: str = "on_demand"        # never continuous


DEFAULT_PROBE_POLICY = ProbePolicy()


def _ts(x) -> float:
    """TZ-safe timestamp: sqlite returns naive datetimes — treat as UTC
    (they were written as UTC) instead of host-local interpretation."""
    if x.tzinfo is None:
        return x.replace(tzinfo=dt.timezone.utc).timestamp()
    return x.timestamp()


def record_sample(session: Session, candidate: str, ok: bool,
                  rtt_ms: float | None = None, jitter_ms: float | None = None,
                  loss_pct: float | None = None, state: str | None = None,
                  node_id: str | None = None) -> HealthSample:
    sample = HealthSample(candidate=candidate, node_id=node_id, ok=ok,
                          rtt_ms=rtt_ms, jitter_ms=jitter_ms,
                          loss_pct=loss_pct, state=state,
                          extra={"policy": "lightweight"})
    session.add(sample)
    session.commit()
    return sample


# ── rollups + retention (§16) ──────────────────────────────────────────

@dataclass
class RetentionPolicy:
    hi_res_keep_s: int = 3600 * 6         # recent raw samples
    aggregate_bucket_s: int = 300         # 5-minute rollup buckets
    keep_buckets: int = 2016              # ~1 week of rollups


@dataclass
class Rollup:
    candidate: str
    bucket_start: float
    availability: float
    rtt_p50: float | None
    rtt_p95: float | None
    jitter_mean: float | None
    loss_mean: float | None
    n: int


def _pct(sorted_xs: list[float], p: float) -> float | None:
    if not sorted_xs:
        return None
    k = int(p * (len(sorted_xs) - 1))
    return sorted_xs[min(k, len(sorted_xs) - 1)]


def rollup(samples: list[HealthSample], bucket_s: int = 300,
           bucket_of=None) -> list[Rollup]:
    """Aggregate samples into fixed buckets (deterministic)."""
    if not samples:
        return []
    keyf = bucket_of or (lambda s: int(_ts(s.ts) // bucket_s) * bucket_s)
    grouped: dict[tuple[str, int], list[HealthSample]] = {}
    for s in samples:
        grouped.setdefault((s.candidate, keyf(s)), []).append(s)
    out = []
    for (candidate, bucket), group in sorted(grouped.items()):
        rtts = sorted(s.rtt_ms for s in group if s.rtt_ms is not None)
        jitters = [s.jitter_ms for s in group if s.jitter_ms is not None]
        losses = [s.loss_pct for s in group if s.loss_pct is not None]
        out.append(Rollup(
            candidate=candidate, bucket_start=bucket,
            availability=sum(1 for s in group if s.ok) / len(group),
            rtt_p50=_pct(rtts, 0.50), rtt_p95=_pct(rtts, 0.95),
            jitter_mean=statistics.fmean(jitters) if jitters else None,
            loss_mean=statistics.fmean(losses) if losses else None,
            n=len(group)))
    return out


def apply_retention(samples: list[HealthSample], now_ts: float,
                    policy: RetentionPolicy | None = None) -> tuple[list, list]:
    """Split into (keep_raw, drop_raw) — raw samples older than the hi-res
    window are dropped after their rollups exist; rollup count is capped."""
    policy = policy or RetentionPolicy()
    cutoff = now_ts - policy.hi_res_keep_s
    keep = [s for s in samples if _ts(s.ts) >= cutoff]
    drop = [s for s in samples if _ts(s.ts) < cutoff]
    return keep, drop


# ── stability history (§17) ────────────────────────────────────────────

@dataclass
class StabilityProfile:
    candidate: str
    availability: float
    failure_rate: float
    rtt_p95: float | None
    jitter_mean: float | None
    loss_mean: float | None
    classification: str                    # FAST_BUT_UNSTABLE | SLOWER_BUT_STABLE | NOMINAL


def stability_profile(samples: list[HealthSample],
                      fast_rtt_ms: float = 50.0,
                      unstable_availability: float = 0.98) -> StabilityProfile | None:
    if not samples:
        return None
    rtts = sorted(s.rtt_ms for s in samples if s.rtt_ms is not None)
    jitters = [s.jitter_ms for s in samples if s.jitter_ms is not None]
    losses = [s.loss_pct for s in samples if s.loss_pct is not None]
    avail = sum(1 for s in samples if s.ok) / len(samples)
    p95 = _pct(rtts, 0.95)
    mean_jitter = statistics.fmean(jitters) if jitters else None
    fast = (p95 or 1e9) <= fast_rtt_ms
    stable = avail >= unstable_availability
    if fast and not stable:
        cls = "FAST_BUT_UNSTABLE"
    elif not fast and stable:
        cls = "SLOWER_BUT_STABLE"
    else:
        cls = "NOMINAL"
    return StabilityProfile(
        candidate=samples[0].candidate, availability=round(avail, 4),
        failure_rate=round(1 - avail, 4), rtt_p95=p95,
        jitter_mean=round(mean_jitter, 3) if mean_jitter is not None else None,
        loss_mean=round(statistics.fmean(losses), 3) if losses else None,
        classification=cls)


# ── optional Prometheus export (§24) ───────────────────────────────────

def prometheus_export(measurements: dict[str, float]) -> str:
    """Minimal text exposition; Prometheus stays OPTIONAL for operation."""
    lines = []
    for name, value in sorted(measurements.items()):
        metric = "tunnelpannel_" + name.replace(" ", "_")
        lines.append(f"# TYPE {metric} gauge")
        lines.append(f'{metric} {value}')
    return "\n".join(lines) + "\n"
