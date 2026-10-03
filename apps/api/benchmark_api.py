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

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.models import BenchmarkReceipt, BenchmarkSample, Job
from orchestrator.benchmarking import PROFILES, resolve_candidates
from orchestrator.benchmarking.runner import BenchmarkRunner, sanitize


class StartRequest(BaseModel):
    node_a: dict            # NodeCaps-like snapshot (binaries, modules, ...)
    node_b: dict
    profile: str = "NORMAL"
    max_parallel: int = 2


def create_router(session_factory, caps_from_dict, adapter_factory) -> APIRouter:
    """caps_from_dict(payload) -> NodeCaps; adapter_factory(candidate) -> adapter."""
    router = APIRouter(prefix="/benchmarks", tags=["benchmark"])
    runners: dict[str, BenchmarkRunner] = {}
    lock = threading.Lock()

    @router.post("")
    def start(req: StartRequest):
        if req.profile not in PROFILES:
            raise HTTPException(400, f"profile must be one of {sorted(PROFILES)}")
        caps_a = caps_from_dict(req.node_a)
        caps_b = caps_from_dict(req.node_b)
        candidates = resolve_candidates(caps_a, caps_b)
        with session_factory() as session:
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
                                 req.profile, adapter_factory, candidates,
                                 max_parallel=req.max_parallel)
        with lock:
            runners[job_id] = runner

        def _run():
            # the worker thread owns its own session + job instance
            with session_factory() as s:
                runner.session = s
                runner.job = s.get(Job, job_id)
                try:
                    runner.run()
                except Exception as e:                     # thread must never die silently
                    if runner.job is not None:
                        runner.job.state = "FAILED"
                        runner.job.error = str(e)[:500]
                        s.commit()

        threading.Thread(target=_run, daemon=True,
                         name=f"bench-{job_id[:8]}").start()
        return {"job_id": job_id, "profile": req.profile,
                "candidates": len(candidates),
                "compatible": sum(1 for c in candidates if c.status == "COMPATIBLE")}

    def _job(job_id: str, session):
        job = session.get(Job, job_id)
        if job is None:
            raise HTTPException(404, "no such benchmark job")
        return job

    @router.get("/{job_id}")
    def state(job_id: str):
        with session_factory() as session:
            job = _job(job_id, session)
            return {"job_id": job.id, "state": job.state, "progress": job.progress,
                    "error": job.error, "payload": job.payload,
                    "created_at": job.created_at, "finished_at": job.finished_at}

    @router.post("/{job_id}/cancel")
    def cancel(job_id: str):
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

    @router.get("/{job_id}/results")
    def results(job_id: str):
        with session_factory() as session:
            job = _job(job_id, session)
            run_id = job.payload.get("_run_id") if job.payload else None
            if run_id is None:
                # find latest run for this job via receipts' documents
                samples = list(session.query(BenchmarkSample).all())
            else:
                samples = list(session.query(BenchmarkSample)
                               .filter(BenchmarkSample.run_id == run_id).all())
            return {"job_id": job_id, "job_state": job.state,
                    "results": [{"candidate": s.candidate, "status": s.status,
                                 "reason": s.reason, "metrics": s.metrics}
                                for s in samples]}

    @router.get("/{job_id}/receipts/{candidate}")
    def receipt(job_id: str, candidate: str):
        with session_factory() as session:
            _job(job_id, session)
            row = (session.query(BenchmarkReceipt)
                   .join(BenchmarkSample, BenchmarkReceipt.sample_id == BenchmarkSample.id)
                   .filter(BenchmarkSample.candidate == candidate)
                   .order_by(BenchmarkReceipt.created_at.desc())
                   .first())
            if row is None:
                raise HTTPException(404, f"no receipt for {candidate}")
            return sanitize(row.document)

    return router
