import threading
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from apps.api.benchmark_api import create_router
from core.models import Base
from engines.adapters import ProbeResult
from orchestrator.benchmarking import Candidate, NodeCaps


def test_completed_candidates_are_visible_while_next_candidate_is_running(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'progress.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    release = threading.Event()
    class Adapter:
        def __init__(self, c): self.c=c
        def configure(self):
            if self.c.legacy_method_id == "IPIP": release.wait(5)
        def start(self): pass
        def probe(self): return ProbeResult(True, "data-plane test seam")
        def metrics(self): return {"rtt_avg": 1.0}
        def rollback(self): pass
    candidates = [Candidate("gre", "default", "GRE", "kernel", "COMPATIBLE"),
                  Candidate("ipip", "default", "IPIP", "kernel", "COMPATIBLE")]
    app = FastAPI()
    app.include_router(create_router(factory, None, None,
        prepare=lambda req: (NodeCaps("a"), NodeCaps("b"), candidates, Adapter)))
    client = TestClient(app)
    job = client.post("/benchmarks", json={"node_a": {}, "node_b": {}, "max_parallel": 1}).json()["job_id"]
    try:
        rows = []
        for _ in range(20):
            rows = client.get(f"/benchmarks/{job}/results").json()["results"]
            if rows: break
            time.sleep(.05)
        assert [r["candidate"] for r in rows] == ["GRE"]
        assert client.get(f"/benchmarks/{job}").json()["state"] == "RUNNING"
    finally:
        release.set()
        for _ in range(100):
            if client.get(f"/benchmarks/{job}").json()["state"] != "RUNNING": break
            time.sleep(.02)


def test_receipt_write_failure_finishes_job_instead_of_waiting_forever(tmp_path, monkeypatch):
    from orchestrator.benchmarking.runner import BenchmarkRunner
    engine = create_engine(f"sqlite:///{tmp_path / 'receipt-failure.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    cleaned = []
    class Adapter:
        def configure(self): pass
        def start(self): pass
        def probe(self): return ProbeResult(True, 'data-plane test seam')
        def metrics(self): return {'rtt_avg': 1.0}
        def rollback(self): cleaned.append(True)
    def broken(*args): raise RuntimeError('receipt store unavailable')
    monkeypatch.setattr(BenchmarkRunner, '_persist_result', broken)
    candidate = Candidate('gre', 'default', 'GRE', 'kernel', 'COMPATIBLE')
    app = FastAPI()
    app.include_router(create_router(factory, None, None,
        prepare=lambda req: (NodeCaps('a'), NodeCaps('b'), [candidate], lambda cand: Adapter())))
    client = TestClient(app)
    job = client.post('/benchmarks', json={'node_a': {}, 'node_b': {}}).json()['job_id']
    for _ in range(60):
        state = client.get(f'/benchmarks/{job}').json()['state']
        if state not in ('QUEUED', 'RUNNING'): break
        time.sleep(.05)
    assert state == 'FAILED'
    assert cleaned == [True]
