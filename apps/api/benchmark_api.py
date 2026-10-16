"""Benchmark HTTP API (P6 §33) — non-blocking Job semantics.

Mountable FastAPI router:
    POST /benchmarks                 start (node_a, node_b, profile) -> job_id
    GET  /benchmarks/{job_id}        job state + progress
    POST /benchmarks/{job_id}/cancel cancel
    GET  /benchmarks/{job_id}/results  ranked results (best → worst)
    GET  /benchmarks/{job_id}/receipts/{candidate}  sanitized receipt

The HTTP request never waits for the benchmark: execution happens on a
background thread recorded as a Job row (finite states, timeouts).
"""
from __future__ import annotations

import threading

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from core.models import BenchmarkReceipt, BenchmarkSample, Job
from core.security import require_role
from orchestrator.benchmarking import PROFILES, resolve_candidates
from orchestrator.benchmarking.runner import BenchmarkRunner, sanitize


class StartRequest(BaseModel):
    node_a: dict            # NodeCaps-like snapshot (binaries, modules, ...)
    node_b: dict
    profile: str = "NORMAL"
    max_parallel: int = Field(default=2, ge=1, le=2)
    methods: list[str] | None = None


def create_router(session_factory, caps_from_dict, adapter_factory,
                  execution_available: bool = True, prepare=None, secure=False) -> APIRouter:
    """caps_from_dict(payload) -> NodeCaps; adapter_factory(candidate) -> adapter."""
    router = APIRouter(prefix="/benchmarks", tags=["benchmark"])
    runners: dict[str, BenchmarkRunner] = {}
    lock = threading.Lock()
    from orchestrator.standalone_benchmarks import StandaloneBenchmarkService
    service = StandaloneBenchmarkService(lambda: BenchmarkRunner) if secure else None
    router.service = service

    mutations = [Depends(require_role("SUPER_ADMIN", "OPERATOR"))] if secure else []
    reads = [Depends(require_role("SUPER_ADMIN", "OPERATOR", "VIEWER"))] if secure else []

    @router.get("/methods", dependencies=reads)
    def methods():
        from core.catalog import CATALOG
        from orchestrator.mesh_campaign import capability, failure_domain
        from orchestrator.mesh_persistent import egress_supported
        from orchestrator.mesh_quality import encryption
        return [{"id": i.legacy_id, "engine": i.engine, "profile": i.profile,
                 "composite": i.is_composite, "capability": capability(i.legacy_id),
                 "failure_domain": failure_domain(i.legacy_id),
                 'encryption': encryption(i.legacy_id),
                 "persistent_tcp_egress": egress_supported(i.legacy_id)} for i in CATALOG.identities.values()]

    @router.get("", dependencies=reads)
    def history():
        with session_factory() as session:
            jobs = session.query(Job).filter_by(kind="benchmark").order_by(Job.created_at.desc()).limit(30).all()
            return [{"job_id": j.id, "state": j.state, "profile": j.payload.get("profile"),
                     "created_at": j.created_at} for j in jobs]

    @router.post("", dependencies=mutations)
    def start(req: StartRequest):
        if not execution_available:
            raise HTTPException(503, "real-node benchmark execution is not configured; no job was started")
        if req.profile not in PROFILES:
            raise HTTPException(400, f"profile must be one of {sorted(PROFILES)}")
        from core.workspaces import active_test_count, scope_limits, workspace_context
        scope = workspace_context.get()
        customer = scope and scope['id'] != 'system'
        limits = scope_limits()
        if customer and (limits['max_nodes'] < 2 or req.methods is not None and (
                not req.methods or len(req.methods) != len(set(req.methods)) or
                len(req.methods) > limits['max_campaign_methods'])):
            raise HTTPException(400, 'workspace method or node limit exceeded')
        if prepare:
            caps_a, caps_b, candidates, factory = prepare(req)
        else:
            caps_a = caps_from_dict(req.node_a)
            caps_b = caps_from_dict(req.node_b)
            candidates = resolve_candidates(caps_a, caps_b)
            factory = adapter_factory
        if customer and len(candidates) > limits['max_campaign_methods']:
            raise HTTPException(400, 'workspace method limit exceeded')
        if service:
            return service.create(session_factory, req, caps_a, caps_b, candidates, limits)
        with session_factory() as session:
            if customer:
                if session.bind.dialect.name == 'sqlite':
                    from sqlalchemy import text
                    session.execute(text('BEGIN IMMEDIATE'))
                if active_test_count(session) >= limits['max_active_campaigns']:
                    raise HTTPException(409, 'workspace already has its allowed active tests')
            job = Job(kind="benchmark",
                      payload={"node_a": caps_a.node_id, "node_b": caps_b.node_id,
                               "profile": req.profile,
                               "candidates": len(candidates),
                               "compatible": sum(1 for c in candidates
                                                 if c.status == "COMPATIBLE")},
                      timeout_s=PROFILES[req.profile].overall_timeout_s)
            session.add(job)
            session.commit()
            job_id = job.id
        runner = BenchmarkRunner(None, caps_a.node_id, caps_b.node_id,
                                 req.profile, factory, candidates,
                                 max_parallel=req.max_parallel)
        with lock:
            runners[job_id] = runner

        from core.workspaces import freeze_factory
        worker_factory = freeze_factory(session_factory)

        def _run():
            # the worker thread owns its own session + job instance
            with worker_factory() as s:
                runner.session = s
                runner.job = s.get(Job, job_id)
                try:
                    runner.run()
                except Exception as e:                     # thread must never die silently
                    s.rollback()
                    runner.job = s.get(Job, job_id)
                    if runner.job is not None:
                        runner.job.state = "FAILED"
                        runner.job.error = str(e)[:500]
                        s.commit()
                finally:
                    with lock:
                        runners.pop(job_id, None)

        threading.Thread(target=_run, daemon=True,
                         name=f"bench-{job_id[:8]}").start()
        return {"job_id": job_id, "profile": req.profile,
                "candidates": len(candidates),
                "compatible": sum(1 for c in candidates if c.status == "COMPATIBLE")}

    def _job(job_id: str, session):
        job = session.get(Job, job_id)
        if job is None or job.kind != 'benchmark':
            raise HTTPException(404, "no such benchmark job")
        return job

    @router.get("/{job_id}", dependencies=reads)
    def state(job_id: str):
        with session_factory() as session:
            job = _job(job_id, session)
            return {"job_id": job.id, "state": job.state, "progress": job.progress,
                    "error": job.error, "payload": job.payload,
                    "created_at": job.created_at, "finished_at": job.finished_at}

    @router.post("/{job_id}/cancel", dependencies=mutations)
    def cancel(job_id: str):
        if service:
            return service.cancel(session_factory, job_id)
        # Ownership must precede access to the process-wide runner registry.
        with session_factory() as session:
            job = _job(job_id, session)
            if (job.payload or {}).get('campaign_id'):
                raise HTTPException(409, 'cancel the parent mesh campaign')
        with lock:
            runner = runners.get(job_id)
        if runner is None:
            with session_factory() as session:
                job = _job(job_id, session)
                if job.state in ("PASS", "FAILED", "CANCELLED", "TIMED_OUT"):
                    return {"job_id": job_id, "state": job.state}
                job.state = "CANCELLED"
                session.commit()
                return {"job_id": job_id, "state": "CANCELLED"}
        runner.cancel()
        return {"job_id": job_id, "state": "cancelling"}

    @router.get("/{job_id}/results", dependencies=reads)
    def results(job_id: str):
        with session_factory() as session:
            job = _job(job_id, session)
            run_id = job.payload.get("_run_id") if job.payload else None
            if run_id is None:
                samples = []
            else:
                samples = list(session.query(BenchmarkSample)
                               .filter(BenchmarkSample.run_id == run_id).all())
            from orchestrator.benchmarking.scoring import score_sample, rank
            scored = rank([score_sample(s.candidate, s.metrics, s.status) for s in samples])
            by_candidate = {s.candidate: s for s in samples}
            return {"job_id": job_id, "job_state": job.state,
                    "results": [{"candidate": s.candidate, "status": s.status,
                                 "score": s.score,
                                 "reason": by_candidate[s.candidate].reason or ("; ".join(s.reasons) if s.status == "DEGRADED" else None),
                                 "scoring_reasons": s.reasons, "metrics": s.metrics}
                                for s in scored]}

    @router.get("/{job_id}/receipts/{candidate}", dependencies=reads)
    def receipt(job_id: str, candidate: str):
        with session_factory() as session:
            job = _job(job_id, session)
            run_id = (job.payload or {}).get("_run_id")
            if not run_id:
                raise HTTPException(404, f"no receipt for {candidate}")
            row = (session.query(BenchmarkReceipt)
                   .join(BenchmarkSample, BenchmarkReceipt.sample_id == BenchmarkSample.id)
                   .filter(BenchmarkSample.candidate == candidate)
                   .filter(BenchmarkSample.run_id == run_id)
                   .order_by(BenchmarkReceipt.created_at.desc())
                   .first())
            if row is None:
                raise HTTPException(404, f"no receipt for {candidate}")
            return sanitize(row.document)

    return router
