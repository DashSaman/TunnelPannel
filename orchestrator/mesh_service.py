"""Durable campaigns reuse the real pair runner and its ownership receipts."""
from __future__ import annotations

import datetime as dt
import hashlib
import threading
import uuid
from types import SimpleNamespace

from fastapi import HTTPException

from core.models import BenchmarkReceipt, BenchmarkSample, Job, Node, NodeInventory
from core.workspaces import active_test_count, freeze_factory
from orchestrator.benchmarking import PROFILES
from orchestrator.benchmarking.runner import BenchmarkRunner
from orchestrator.host_lease import HostLease
from orchestrator.mesh_campaign import directed_routes, recommendations

TERMINAL = {"PASS", "FAILED", "CANCELLED", "TIMED_OUT", "INTERRUPTED"}


def campaign_job(session, campaign_id):
    job = session.get(Job, campaign_id)
    if job is None or job.kind != "mesh_campaign":
        raise HTTPException(404, "campaign not found")
    return job


def route_samples(session, child_id):
    child = session.get(Job, child_id) if child_id else None
    run_id = (child.payload or {}).get("_run_id") if child else None
    if not run_id:
        return []
    rows = session.query(BenchmarkSample).filter_by(run_id=run_id).all()
    return [{"candidate": row.candidate, "status": row.status, "metrics": row.metrics,
             "reason": row.reason, "receipt": session.query(BenchmarkReceipt).filter_by(sample_id=row.id).count() > 0}
            for row in rows]


def campaign_view(session, job):
    payload = job.payload or {}
    routes = []
    for route in payload.get("routes", []):
        child = session.get(Job, route.get("job_id")) if route.get("job_id") else None
        rows = route_samples(session, route.get("job_id"))
        rec = recommendations(rows, payload.get("recommend_count", 5), payload.get("purpose", "any"))
        routes.append({**route, "state": child.state if child else "QUEUED",
                       "progress": child.progress if child else 0,
                       "recommendation": rec, "results": rows,
                       "selection": route.get("selection", rec["selected"])})
    progress = sum(route['progress'] for route in routes) / len(routes) if routes else job.progress
    return {"id": job.id, "state": job.state, "progress": progress,
            "error": job.error, "profile": payload.get("profile"), "routes": routes,
            "created_at": job.created_at, "finished_at": job.finished_at,
            "geography": "measured on the selected physical nodes; locations are operator labels"}


class CampaignService:
    def __init__(self):
        self.prepare = None  # explicit injection seam for unit adapters only
        self._threads = {}
        self._lock = threading.Lock()

    def create(self, factory, request, limits):
        factory = freeze_factory(factory)
        try:
            routes = directed_routes(request.nodes)
        except ValueError as error:
            raise HTTPException(400, str(error)) from None
        if len(request.nodes) > limits["max_nodes"]:
            raise HTTPException(400, "workspace node limit exceeded")
        from core.catalog import CATALOG
        methods = request.methods if request.methods is not None else list(CATALOG.identities)
        if not methods or len(methods) != len(set(methods)) or not set(methods) <= set(CATALOG.identities):
            raise HTTPException(400, "select unique known methods")
        if len(methods) > limits["max_campaign_methods"] or request.recommend_count > limits["max_tunnels_per_route"]:
            raise HTTPException(400, "workspace method limit exceeded")
        with factory() as session:
            # Serialize admission across threads/processes, not just this instance.
            if session.bind.dialect.name == "sqlite":
                from sqlalchemy import text
                session.execute(text("BEGIN IMMEDIATE"))
            nodes = [session.get(Node, node) for node in request.nodes]
            if any(node is None for node in nodes):
                raise HTTPException(400, "all nodes must belong to this workspace")
            fingerprints = [HostLease({'host': node.host, 'host_key_fingerprint': node.host_key_fingerprint}).key
                            for node in nodes]
            if len(set(fingerprints)) != len(nodes) or len({node.host for node in nodes}) != len(nodes):
                raise HTTPException(400, "register distinct physical hosts, not duplicate aliases")
            if any(not session.query(NodeInventory).filter_by(node_id=node.id).first() for node in nodes):
                raise HTTPException(400, "discover every selected node before starting")
            active = active_test_count(session)
            if active >= limits["max_active_campaigns"]:
                raise HTTPException(409, "workspace already has its allowed active campaigns")
            payload = {"nodes": request.nodes, "methods": methods, "profile": request.profile,
                       "recommend_count": request.recommend_count, "purpose": request.purpose,
                       "routes": [{"id": uuid.uuid4().hex, "source": a, "destination": b,
                                   "job_id": None} for a, b in routes]}
            job = Job(kind="mesh_campaign", state="QUEUED", payload=payload,
                      timeout_s=len(routes) * len(methods) * PROFILES[request.profile].overall_timeout_s)
            session.add(job)
            session.commit()
            job_id = job.id
        self.kick(factory, job_id)
        return job_id

    def kick(self, factory, job_id):
        factory = freeze_factory(factory)
        key = str(factory.kw["bind"].url) + ":" + job_id
        with self._lock:
            if key in self._threads:
                return
            def work():
                try:
                    self.run(factory, job_id)
                finally:
                    with self._lock:
                        self._threads.pop(key, None)
            thread = threading.Thread(target=work, daemon=True, name="mesh-" + job_id[:8])
            self._threads[key] = thread
            thread.start()

    def run(self, factory, job_id):
        identity = hashlib.sha256((str(factory.kw["bind"].url) + job_id).encode()).hexdigest()
        lease = HostLease({"host": "campaign:" + identity})
        if not lease.acquire(0):
            return  # another process owns this campaign
        try:
            self._run_claimed(factory, job_id)
        except Exception:
            # SSH exceptions can contain credentials; full diagnostics belong in
            # sanitized per-candidate receipts, not an unfiltered API job error.
            with factory() as session:
                job = campaign_job(session, job_id)
                job.state, job.error = "FAILED", "campaign execution or owned-resource reconciliation failed"
                job.finished_at = dt.datetime.now(dt.timezone.utc)
                session.commit()
        finally:
            lease.release()

    def _run_claimed(self, factory, job_id):
        with factory() as session:
            job = campaign_job(session, job_id)
            if job.state in TERMINAL:
                return
            job.state = "RUNNING"
            job.started_at = job.started_at or dt.datetime.now(dt.timezone.utc)
            session.commit()
            payload = dict(job.payload)
        from orchestrator.pair_runtime import prepare_benchmark
        prepare = self.prepare or prepare_benchmark(factory)
        for index, route in enumerate(payload["routes"]):
            with factory() as session:
                parent = campaign_job(session, job_id)
                if parent.cancel_requested:
                    parent.state = "CANCELLED"
                    parent.finished_at = dt.datetime.now(dt.timezone.utc)
                    session.commit()
                    return
                child = session.get(Job, route["job_id"]) if route["job_id"] else None
                if child and child.state in TERMINAL:
                    continue
                if child:
                    # A process died while this child was active. Reconcile its
                    # exact recorded resources before creating any new deployment.
                    from orchestrator.mesh_reconcile import reconcile_benchmark
                    reconcile_benchmark(factory, child.id)
                    child.state, child.error = "INTERRUPTED", "worker restarted; recorded resources reconciled"
                    session.commit()
                child = Job(kind="benchmark", state="QUEUED",
                            payload={"node_a": route["source"], "node_b": route["destination"],
                                     "profile": payload["profile"], "campaign_id": job_id},
                            timeout_s=len(payload["methods"]) * PROFILES[payload["profile"]].overall_timeout_s)
                session.add(child)
                session.flush()
                route["job_id"] = child.id
                parent.payload = {**parent.payload, "routes": payload["routes"]}
                session.commit()
                child_id = child.id
            request = SimpleNamespace(node_a={"node_id": route["source"]},
                                      node_b={"node_id": route["destination"]},
                                      profile=payload["profile"], methods=payload["methods"])
            caps_a, caps_b, candidates, adapter_factory = prepare(request)
            with factory() as session:
                runner = BenchmarkRunner(session, caps_a.node_id, caps_b.node_id,
                                         payload["profile"], adapter_factory, candidates,
                                         max_parallel=1, job=session.get(Job, child_id))
                stop = threading.Event()
                def watch_cancel():
                    while not stop.wait(.25):
                        with factory() as control:
                            if campaign_job(control, job_id).cancel_requested:
                                runner.cancel()
                                return
                watcher = threading.Thread(target=watch_cancel, daemon=True)
                watcher.start()
                try:
                    runner.run()
                finally:
                    stop.set()
                    watcher.join(timeout=2)
            with factory() as session:
                parent = campaign_job(session, job_id)
                parent.progress = (index + 1) / len(payload["routes"])
                session.commit()
        with factory() as session:
            job = campaign_job(session, job_id)
            view = campaign_view(session, job)
            job.state = ("CANCELLED" if job.cancel_requested else
                         "PASS" if all(r["recommendation"]["qualified"] for r in view["routes"]) else "FAILED")
            job.progress = 1
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            session.commit()

    def recover(self, factory):
        with factory() as session:
            ids = [job.id for job in session.query(Job).filter(Job.kind == "mesh_campaign",
                    Job.state.in_(["QUEUED", "RUNNING"]))]
        for job_id in ids:
            self.kick(factory, job_id)
