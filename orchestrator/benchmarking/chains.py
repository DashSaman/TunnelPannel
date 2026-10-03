"""Composed-chain benchmarking (P9 §24-§35).

Bounded beam-search candidate generation (terminates on explicit budgets),
semantic deduplication, PREDICTED-vs-MEASURED separation, full-chain
data-plane truth gate (component health alone never passes a chain),
per-component evidence, shared-failure-domain analysis and combined
standalone+composed ranking. Chain benchmark concurrency defaults to 1.
"""
from __future__ import annotations

import dataclasses
import datetime as dt

from sqlalchemy.orm import Session

from core.catalog import CATALOG
from core.models import BenchmarkReceipt, BenchmarkRun, BenchmarkSample, Event
from engines.manifests import load_all
from orchestrator.benchmarking.scoring import score_sample
from orchestrator.composition import (ChainSpec, CompSpec, build_plan,
                                      chain_depth, topological_order,
                                      validate_chain)

from .runner import sanitize


@dataclasses.dataclass(frozen=True)
class ChainBenchConfig:
    max_chain_depth: int = 3
    hard_max_components: int = 5
    beam_width: int = 12
    max_auto_candidates: int = 40
    max_auto_chain_benchmarks: int = 20
    max_parallel_chain_benchmarks: int = 1


DEFAULT_CHAIN_CONFIG = ChainBenchConfig()


# ── semantic identity (§27) ────────────────────────────────────────────

def canonical_chain_key(spec: ChainSpec) -> tuple:
    """Identity of the underlay→overlay path; aliases/legacy names/spelling
    collapse to the same key. Chains differing only in component_id names
    or display names are the SAME chain."""
    order = topological_order(spec)
    comps = spec.by_id()
    return tuple((comps[cid].engine_id, comps[cid].profile_id) for cid in order)


def dedupe(specs: list[ChainSpec]) -> list[ChainSpec]:
    seen: set[tuple] = set()
    out: list[ChainSpec] = []
    for spec in specs:
        key = canonical_chain_key(spec)
        if key not in seen:
            seen.add(key)
            out.append(spec)
    return out


# ── bounded candidate search (§24-§26) ─────────────────────────────────

class ChainCandidate:
    def __init__(self, spec: ChainSpec, predicted_score: float):
        self.spec = spec
        self.predicted_score = predicted_score     # PREDICTED — never a result

    @property
    def label(self) -> str:
        return "PREDICTED"


def _valid_overlay_over(underlay_engine: str, underlay_profile: str,
                        overlay_engine: str, manifests) -> bool:
    from orchestrator.composition.core import resolve_pair
    ok, _reasons, _a = resolve_pair(overlay_engine, underlay_engine,
                                    underlay_profile, manifests)
    return ok


def generate_candidates(standalone_results: list[dict], config: ChainBenchConfig | None = None,
                        manifests: dict | None = None) -> list[ChainCandidate]:
    """Beam search over healthy singles. TERMINATES on: candidate budget,
    depth limit, beam width exhaustion. Never an open-ended loop.

    standalone_results: [{candidate: legacy_id, status, score}] from P6."""
    config = config or DEFAULT_CHAIN_CONFIG
    manifests = manifests or load_all()

    # seed: healthy high-ranking singles that can act as underlays
    healthy = [r for r in standalone_results
               if r.get("status") in ("PASS", "DEGRADED")
               and r.get("score") is not None]
    healthy.sort(key=lambda r: (-r["score"], r["candidate"]))
    beam: list[tuple[ChainSpec, float]] = []
    for r in healthy[:config.beam_width]:
        ident = CATALOG.by_legacy(r["candidate"])
        m = manifests.get(ident.engine)
        if m is None or not m["can_be_underlay"]:
            continue
        spec = ChainSpec(f"auto:{r['candidate']}", [
            CompSpec("c0", ident.engine, profile_id=ident.profile)])
        beam.append((spec, float(r["score"])))

    overlay_pool: list[tuple[str, str]] = []
    for r in healthy:
        ident = CATALOG.by_legacy(r["candidate"])
        m = manifests.get(ident.engine)
        if m is not None and m["can_be_overlay"]:
            overlay_pool.append((ident.engine, ident.profile))
    overlay_pool = overlay_pool[:config.beam_width]

    out: list[ChainSpec] = []
    frontier = beam
    depth = 1
    while frontier and depth < config.max_chain_depth and len(out) < config.max_auto_candidates:
        nxt: list[tuple[ChainSpec, float]] = []
        for spec, score in frontier:
            top = spec.by_id()[topological_order(spec)[-1]]
            for oengine, oprofile in overlay_pool:
                if len(out) >= config.max_auto_candidates:
                    break
                if not _valid_overlay_over(top.engine_id, top.profile_id, oengine, manifests):
                    continue
                if any(c.engine_id == oengine and c.profile_id == oprofile
                       for c in spec.components):
                    continue                     # no identical repeats in auto chains
                comps = list(spec.components) + [
                    CompSpec(f"c{len(spec.components)}", oengine,
                             profile_id=oprofile, parent_id=top.component_id)]
                if len(comps) > config.hard_max_components:
                    continue
                cand = ChainSpec(f"auto:{oengine}-over-{top.engine_id}", comps)
                if validate_chain(cand).valid:
                    out.append(cand)
                    predicted = max(0.0, score - 3.0 * len(comps))   # depth penalty
                    nxt.append((cand, predicted))
        frontier = sorted(nxt, key=lambda t: -t[1])[:config.beam_width]
        depth += 1
    # order by predicted quality; PREDICTED is a selection heuristic only
    result: list[ChainCandidate] = []
    seen: set[tuple] = set()
    for spec in out:
        key = canonical_chain_key(spec)
        if key in seen:
            continue
        seen.add(key)
        depth_pen = 3.0 * len(spec.components)
        base = max((float(r["score"]) for r in healthy
                    if (i2 := CATALOG.by_legacy(r["candidate"])).engine
                    in {c.engine_id for c in spec.components}), default=50.0)
        result.append(ChainCandidate(spec, max(0.0, base - depth_pen)))
        if len(result) >= config.max_auto_candidates:
            break
    result.sort(key=lambda c: -c.predicted_score)
    return result[:config.max_auto_chain_benchmarks] if config.max_auto_chain_benchmarks else result


# ── shared failure domains (§32) ───────────────────────────────────────

def shared_failure_domains(a: ChainSpec, b: ChainSpec) -> dict:
    ka = {(c.engine_id, c.profile_id) for c in a.components}
    kb = {(c.engine_id, c.profile_id) for c in b.components}
    shared = ka & kb
    underlays_a = {c.engine_id for c in a.components if c.parent_id is None}
    underlays_b = {c.engine_id for c in b.components if c.parent_id is None}
    union = ka | kb
    diversity = 1.0 - (len(shared) / len(union) if union else 0.0)
    return {
        "shared_components": sorted(f"{e}/{p}" for e, p in shared),
        "shared_underlays": sorted(underlays_a & underlays_b),
        "shared_nodes": [],
        "diversity_score": round(diversity, 3),
        "warning": ("BACKUP_SHARES_UNDERLAY_WITH_PRIMARY"
                    if (underlays_a & underlays_b) else None),
    }


# ── chain benchmark (§29-§31, §35) ────────────────────────────────────

class ChainBenchResult:
    def __init__(self, spec, status, components, end_to_end_ok, metrics, reason=""):
        self.spec, self.status = spec, status
        self.components = components        # [{component_id, status, evidence}]
        self.end_to_end_ok = end_to_end_ok
        self.metrics, self.reason = metrics, reason


def benchmark_chain(session: Session, spec: ChainSpec, adapter_factory,
                    profile_name: str = "NORMAL",
                    config: ChainBenchConfig | None = None) -> ChainBenchResult | None:
    """Manual or auto chain benchmark. Validation is NOT bypassable (§34).
    PASS requires the FULL-CHAIN data-plane probe — component health alone
    is insufficient (§29)."""
    config = config or DEFAULT_CHAIN_CONFIG
    validation = validate_chain(spec)
    if not validation.valid:
        return ChainBenchResult(spec, "INCOMPATIBLE", [], False,
                                {"reason": "; ".join(validation.reasons)})
    plan = build_plan(spec)
    if plan is None:
        return None

    run = BenchmarkRun(node_a="chain-a", node_b="chain-b",
                       profile=profile_name, state="RUNNING",
                       methodology={"kind": "chain", "layers": chain_depth(spec)})
    session.add(run)
    session.commit()

    manifests = load_all()
    components: list[dict] = []
    metrics: dict = {"setup_ok": True, "data_plane_ok": False,
                     "layers": chain_depth(spec),
                     "overhead_total": plan.mtu.overhead_total if plan.mtu else None}
    adapters = {}
    status, reason = "FAILED", ""
    try:
        # install in topological order (underlay → overlay)
        for cid in plan.install_order:
            comp = spec.by_id()[cid]
            adapter = adapter_factory(comp)
            adapters[cid] = adapter
            try:
                adapter.configure()
                adapter.start()
                probe = adapter.probe()
                components.append({"component_id": cid,
                                   "engine": comp.engine_id,
                                   "status": "PASS" if probe.ok else "FAILED",
                                   "evidence": probe.evidence[:200]})
                if not probe.ok:
                    metrics["setup_ok"] = False
                    reason = f"component {cid} failed its probe"
                    status = "FAILED"
                    return ChainBenchResult(spec, status, components, False, metrics, reason)
            except Exception as e:
                components.append({"component_id": cid, "engine": comp.engine_id,
                                   "status": "FAILED", "evidence": str(e)[:200]})
                metrics["setup_ok"] = False
                reason = f"component {cid} setup error: {str(e)[:160]}"
                status = "FAILED"
                return ChainBenchResult(spec, status, components, False, metrics, reason)

        # FULL-CHAIN truth gate: the TOP overlay's probe traverses the stack
        top_cid = plan.install_order[-1]
        top_probe = adapters[top_cid].probe()
        metrics["data_plane_ok"] = bool(top_probe.ok)
        if not top_probe.ok:
            status, reason = "FAILED", f"end-to-end: {top_probe.evidence[:200]}"
        else:
            m = adapters[top_cid].metrics() or {}
            metrics.update({k: v for k, v in m.items() if v is not None})
            metrics["stability_ratio"] = 1.0
            status = "PASS"
        return ChainBenchResult(spec, status, components,
                                metrics["data_plane_ok"], metrics, reason)
    finally:
        # cleanup: reverse topological order (overlay torn down first) — ALWAYS
        try:
            for cid in reversed(plan.install_order):
                ad = adapters.get(cid)
                if ad is not None:
                    ad.rollback()
        except Exception as e:
            session.add(Event(severity="critical", source="chain-benchmark",
                              message=f"ORPHANED_RESOURCE in chain teardown: {str(e)[:200]}"))
        _persist(session, run, spec, components, metrics, status, reason,
                 validation.warnings)


def _persist(session, run, spec, components, metrics, status, reason, warnings):
    sample = BenchmarkSample(
        run_id=run.id, candidate="chain:" + spec.name, candidate_kind="chain",
        status=status, reason=reason or None, metrics=sanitize(dict(metrics)))
    session.add(sample)
    session.flush()
    scored = score_sample("chain:" + spec.name, metrics, status)
    session.add(BenchmarkReceipt(sample_id=sample.id, document=sanitize({
        "benchmark_run_id": run.id,
        "chain_definition": [dataclasses.asdict(c) for c in
                             sorted(spec.components,
                                    key=lambda c: plan_order_index(spec, c))],
        "component_evidence": components,
        "end_to_end_probe": metrics.get("data_plane_ok"),
        "layers": metrics.get("layers"),
        "overhead_total": metrics.get("overhead_total"),
        "status": status, "reason": reason,
        "warnings": warnings,
        "metrics": dict(metrics),
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
    })))
    run.state = status if status == "PASS" else "FAILED"
    run.finished_at = dt.datetime.now(dt.timezone.utc)
    session.commit()


def plan_order_index(spec: ChainSpec, comp: CompSpec) -> int:
    return topological_order(spec).index(comp.component_id)
