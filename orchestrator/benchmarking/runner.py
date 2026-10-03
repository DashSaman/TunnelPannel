"""Benchmark runner (P6 §18-§20, §26-§27, §32-§34).

Bounded concurrent execution of every COMPATIBLE standalone candidate:
temporary owned resources via the P4 ResourceManager, per-stage timeouts,
cancellation, always-attempted cleanup (ORPHANED_RESOURCE events on
failure), raw metrics persisted BEFORE scoring, sanitized receipts, Job
semantics (no job stays RUNNING forever).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import threading
import time
from typing import Callable

from sqlalchemy.orm import Session

from core.models import (BenchmarkReceipt, BenchmarkRun, BenchmarkSample,
                         Deployment, Event, Job)
from orchestrator.resources import ResourceManager

from . import DEFAULT_MAX_PARALLEL, PROFILES, Candidate
from .scoring import ScoredSample, rank, score_sample

_RESULT_STATES = ("PASS", "DEGRADED", "FAILED", "BLOCKED", "INCOMPATIBLE",
                  "CANCELLED", "TIMED_OUT")

SANITIZE_KEYS = ("password", "psk", "auth", "token", "auth_token",
                 "pairing_token", "private_key", "user_id", "noise_key")


def sanitize(obj) -> object:
    """Deep redaction of secret-ish keys from anything persisted/emitted."""
    if isinstance(obj, dict):
        return {k: ("***REDACTED***" if any(s in k.lower() for s in SANITIZE_KEYS)
                    and isinstance(v, str) and v else sanitize(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    if isinstance(obj, str) and len(obj) > 400:
        return obj[:400] + "…"          # evidence truncation
    return obj


class _StageTimeout(Exception):
    pass


@dataclasses.dataclass
class BenchResult:
    candidate: Candidate
    status: str
    metrics: dict
    reason: str = ""


class BenchmarkRunner:
    """One bounded benchmark run. Adapter_factory(candidate) -> adapter-like
    object (P5 adapters in production; fakes in tests)."""

    def __init__(self, session: Session, node_a_id: str, node_b_id: str,
                 profile_name: str = "NORMAL",
                 adapter_factory: Callable[[Candidate], object] | None = None,
                 candidates: list[Candidate] | None = None,
                 max_parallel: int = DEFAULT_MAX_PARALLEL,
                 job: Job | None = None):
        if profile_name not in PROFILES:
            raise ValueError(f"unknown profile {profile_name}")
        self.session = session
        self.profile = PROFILES[profile_name]
        self.max_parallel = max(1, int(max_parallel))
        self.adapter_factory = adapter_factory
        self.candidates = candidates or []
        self.job = job
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()      # serialize shared-session DB access
        self.orphaned: list[str] = []
        self._run: BenchmarkRun | None = None

    # ── job plumbing ──
    def _set_job(self, state: str, progress: float, error: str | None = None) -> None:
        if self.job is None:
            return
        with self._db_lock:
            self._set_job_locked(state, progress, error)

    def _set_job_locked(self, state: str, progress: float, error: str | None = None) -> None:
        self.job.state = state
        self.job.progress = progress
        if error:
            self.job.error = error[:500]
        if state in _RESULT_STATES or state == "PASS":
            self.job.finished_at = dt.datetime.now(dt.timezone.utc)
        self.session.commit()

    def cancel(self) -> None:
        self._cancel.set()

    # ── one candidate ──
    def _bench_one(self, cand: Candidate) -> BenchResult:
        if cand.status != "COMPATIBLE":
            return BenchResult(cand, cand.status, {"reason": cand.reason})
        if self._cancel.is_set():
            return BenchResult(cand, "CANCELLED", {"reason": "run cancelled"})

        prof = self.profile
        deadline = time.monotonic() + prof.overall_timeout_s
        with self._db_lock:
            deployment = Deployment(node_a="bench-a", node_b="bench-b",
                                    state="APPLYING",
                                    desired_state={"benchmark": True, "candidate": cand.legacy_method_id})
            self.session.add(deployment)
            self.session.flush()
        rm = ResourceManager(self.session)
        adapter = self.adapter_factory(cand) if self.adapter_factory else None
        metrics: dict = {"setup_ok": False, "data_plane_ok": False}
        status, reason = "FAILED", ""
        try:
            # temporary owned resource (benchmark isolation §18)
            with self._db_lock:
                rm.allocate_temp(key=f"bench-{deployment.id[:8]}-{cand.legacy_method_id}",
                                 deployment_id=deployment.id,
                                 meta={"benchmark": True, "temporary": True,
                                       "candidate": cand.legacy_method_id})
                self.session.commit()
            try:
                if time.monotonic() > deadline:
                    raise _StageTimeout("overall")
                # setup
                t0 = time.monotonic()
                adapter.configure()
                adapter.start()
                metrics["setup_ok"] = True
                metrics["setup_s"] = round(time.monotonic() - t0, 2)
                if time.monotonic() > deadline:
                    raise _StageTimeout("overall")
            except _StageTimeout:
                raise
            except Exception as e:
                reason = f"setup failed: {str(e)[:160]}"
                raise

            # data-plane probes
            probe = adapter.probe()
            if time.monotonic() > deadline:
                raise _StageTimeout("overall")
            metrics["data_plane_ok"] = bool(probe.ok)
            if not probe.ok:
                status, reason = "FAILED", f"data-plane: {probe.evidence[:200]}"
                return BenchResult(cand, status, metrics, reason)

            # metrics collection (adapter.metrics + probe extras)
            m = adapter.metrics() or {}
            if time.monotonic() > deadline:
                raise _StageTimeout("overall")
            metrics.update({k: v for k, v in m.items() if v is not None})
            if probe.rtt_ms is not None:
                metrics.setdefault("rtt_avg", probe.rtt_ms)
            metrics["stability_ratio"] = 1.0 if metrics.get("data_plane_ok") else 0.0
            status = "PASS"
            return BenchResult(cand, status, metrics, reason)
        except _StageTimeout:
            status, reason = "TIMED_OUT", "overall timeout"
            return BenchResult(cand, status, metrics, reason)
        except Exception as e:
            if not reason:
                reason = str(e)[:200]
            metrics.setdefault("reason", reason)
            return BenchResult(cand, status or "FAILED", metrics, reason)
        finally:
            # cleanup ALWAYS attempted (§18); orphans surfaced
            try:
                if adapter is not None:
                    adapter.rollback()
                with self._db_lock:
                    n = rm.release_deployment(deployment.id)
                    self.session.commit()
                metrics["cleanup"] = f"released {n}"
            except Exception as e:
                with self._db_lock:
                    self.orphaned.append(cand.legacy_method_id)
                    self.session.add(Event(severity="critical", source="benchmark",
                                           message=f"ORPHANED_RESOURCE after {cand.legacy_method_id}: {str(e)[:200]}",
                                           context={"candidate": cand.legacy_method_id}))
                    self.session.commit()
                metrics["cleanup"] = f"ORPHANED: {str(e)[:120]}"

    # ── bounded scheduling ──
    def run(self) -> list[ScoredSample]:
        self._set_job("RUNNING", 0.0)
        self._run = BenchmarkRun(node_a="bench-a", node_b="bench-b",
                                 profile=self.profile.name,
                                 methodology=self.profile.methodology,
                                 state="RUNNING")
        self.session.add(self._run)
        self.session.commit()

        results: list[BenchResult] = []
        work = list(self.candidates)
        total = len(work)
        done = 0
        sem = threading.Semaphore(self.max_parallel)
        cv = threading.Condition()
        errors: list[Exception] = []

        def worker(cand: Candidate) -> None:
            with sem:
                if self._cancel.is_set():
                    res = BenchResult(cand, "CANCELLED", {"reason": "run cancelled"})
                else:
                    try:
                        res = self._bench_one(cand)
                    except Exception as e:               # defensive: never kills the run
                        errors.append(e)
                        res = BenchResult(cand, "FAILED", {"reason": f"runner error: {e}"})
            with cv:
                results.append(res)
                nonlocal done
                done += 1
                self._set_job("RUNNING", min(done / total, 0.99) if total else 1.0)
                cv.notify_all()

        threads = [threading.Thread(target=worker, args=(c,), daemon=True)
                   for c in work]
        for t in threads:
            t.start()
        with cv:
            while done < total:
                cv.wait(timeout=1.0)
                if self._cancel.is_set() and done < total:
                    cv.wait(timeout=2.0)                 # let in-flight finish/cancel

        # persist raw samples FIRST (§27), then score
        scored: list[ScoredSample] = []
        for res in results:
            sample = BenchmarkSample(
                run_id=self._run.id, candidate=res.candidate.legacy_method_id,
                candidate_kind="single", status=res.status,
                reason=res.reason or None,
                metrics=sanitize(dict(res.metrics)))
            self.session.add(sample)
            self.session.flush()
            s = score_sample(res.candidate.legacy_method_id, res.metrics, res.status)
            scored.append(s)
            self.session.add(BenchmarkReceipt(
                sample_id=sample.id,
                document=sanitize({
                    "benchmark_run_id": self._run.id,
                    "candidate_id": res.candidate.engine + "/" + res.candidate.profile,
                    "method_id": res.candidate.legacy_method_id,
                    "engine": res.candidate.engine, "profile": res.candidate.profile,
                    "profile_name": self.profile.name,
                    "methodology": self.profile.methodology,
                    "status": res.status, "reason": res.reason,
                    "metrics": dict(res.metrics),
                    "orphaned": res.candidate.legacy_method_id in self.orphaned,
                    "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
                })))
        self.session.commit()

        ranked = rank(scored)
        final = "PASS" if ranked and ranked[0].status in ("PASS", "DEGRADED") else \
                "CANCELLED" if self._cancel.is_set() else "FAILED"
        self._run.state = final
        self._run.finished_at = dt.datetime.now(dt.timezone.utc)
        self._set_job(final, 1.0)
        return ranked
