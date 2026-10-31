"""Durable standalone queue sharing campaign quota and process-wide slots."""
import datetime as dt
import hashlib
import threading
from types import SimpleNamespace

from fastapi import HTTPException

from core.models import Job
from core.workspaces import active_test_count, freeze_factory
from orchestrator.benchmarking import PROFILES
from orchestrator.campaign_budget import reserve_fields
from orchestrator.host_lease import HostLease

TERMINAL = {'PASS', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'INTERRUPTED'}


class StandaloneBenchmarkService:
    def __init__(self, runner_class):
        self.runner_class = runner_class
        self.running = set()
        self.runners = {}
        self.lock = threading.Lock()

    def create(self, factory, request, caps_a, caps_b, candidates, limits):
        factory = freeze_factory(factory)
        with factory() as session:
            if session.bind.dialect.name == 'sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            if active_test_count(session) >= limits['max_active_campaigns']:
                raise HTTPException(409, 'workspace already has its allowed active tests')
            reservation = reserve_fields(session, len(candidates), limits)
            # Never persist arbitrary input dictionaries, capabilities or credentials.
            payload = {'node_a': caps_a.node_id, 'node_b': caps_b.node_id, 'profile': request.profile,
                       'candidates': len(candidates), **reservation,
                       'compatible': sum(c.status == 'COMPATIBLE' for c in candidates),
                       '_queued_request': {'node_a': {'node_id': caps_a.node_id},
                          'node_b': {'node_id': caps_b.node_id}, 'profile': request.profile,
                          'methods': [c.legacy_method_id for c in candidates], 'max_parallel': request.max_parallel}}
            job = Job(kind='benchmark', state='QUEUED', payload=payload,
                      timeout_s=len(candidates)*PROFILES[request.profile].overall_timeout_s)
            session.add(job)
            session.commit()
            identity = job.id
        self.kick(factory, identity)
        return {'job_id': identity, 'profile': request.profile,
                'candidates': payload['candidates'], 'compatible': payload['compatible']}

    def kick(self, factory, identity):
        from orchestrator.worker_slots import dispatch
        factory = freeze_factory(factory)
        key = str(factory.kw['bind'].url) + ':' + identity
        with self.lock:
            if key in self.running:
                return
            self.running.add(key)
            def work():
                try:
                    self.run(factory, identity, key)
                finally:
                    with self.lock:
                        self.running.discard(key)
            if not dispatch(work, 'benchmark-' + identity[:8]):
                self.running.discard(key)

    def run(self, factory, identity, key):
        lease = HostLease({'host': 'standalone-job:' + hashlib.sha256(key.encode()).hexdigest()})
        if not lease.acquire(0):
            return
        try:
            with factory() as session:
                job = session.get(Job, identity)
                if job is None or job.state in TERMINAL:
                    return
                if job.started_at is not None or job.state == 'RUNNING':
                    from orchestrator.mesh_reconcile import reconcile_benchmark
                    reconcile_benchmark(factory, identity)
                    job.state, job.error = 'INTERRUPTED', 'worker restarted; owned resources reconciled'
                    job.finished_at = dt.datetime.now(dt.timezone.utc)
                    session.commit()
                    return
                if job.cancel_requested:
                    job.state = 'CANCELLED'
                    session.commit()
                    return
                job.state, job.started_at = 'RUNNING', dt.datetime.now(dt.timezone.utc)
                session.commit()
                request = SimpleNamespace(**job.payload['_queued_request'])
                from orchestrator.pair_runtime import prepare_benchmark
                a, b, candidates, adapter = prepare_benchmark(factory)(request)
                runner = self.runner_class()(None, a.node_id, b.node_id, request.profile,
                                             adapter, candidates, max_parallel=request.max_parallel)
                runner.session, runner.job = session, job
                with self.lock:
                    self.runners[key] = runner
                stop = threading.Event()
                def watch():
                    while not stop.wait(.25):
                        with factory() as control:
                            if control.get(Job, identity).cancel_requested:
                                runner.cancel()
                                return
                watcher = threading.Thread(target=watch, daemon=True)
                watcher.start()
                try:
                    runner.run()
                finally:
                    stop.set()
                    watcher.join(2)
        except Exception:
            with factory() as session:
                job = session.get(Job, identity)
                job.state, job.error = 'FAILED', 'benchmark execution or owned-resource reconciliation failed'
                job.finished_at = dt.datetime.now(dt.timezone.utc)
                session.commit()
        finally:
            with self.lock:
                self.runners.pop(key, None)
            lease.release()

    def cancel(self, factory, identity):
        with factory() as session:
            job = session.get(Job, identity)
            if job is None or job.kind != 'benchmark':
                raise HTTPException(404, 'no such benchmark job')
            if job.payload.get('campaign_id'):
                raise HTTPException(409, 'cancel the parent mesh campaign')
            if job.state in TERMINAL:
                return {'job_id': identity, 'state': job.state}
            job.cancel_requested = True
            if job.state == 'QUEUED':
                job.state, job.finished_at = 'CANCELLED', dt.datetime.now(dt.timezone.utc)
            session.commit()
            state = job.state
        key = str(freeze_factory(factory).kw['bind'].url) + ':' + identity
        with self.lock:
            runner = self.runners.get(key)
            if runner:
                runner.cancel()
        return {'job_id': identity, 'state': state}

    def recover(self, factory):
        with factory() as session:
            ids = [j.id for j in session.query(Job).filter(Job.kind == 'benchmark',
                    Job.state.in_(['QUEUED', 'RUNNING'])) if j.payload.get('_queued_request')]
        for identity in ids:
            self.kick(factory, identity)
