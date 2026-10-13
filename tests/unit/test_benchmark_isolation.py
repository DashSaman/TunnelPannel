from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from apps.api.benchmark_api import create_router
from core.models import Base, BenchmarkRun, BenchmarkSample, BenchmarkReceipt, Job


def test_results_and_receipts_are_scoped_to_the_requested_job(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'isolation.db').as_posix()}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as s:
        run = BenchmarkRun(node_a="a", node_b="b", profile="QUICK", state="PASS")
        s.add(run); s.flush()
        sample = BenchmarkSample(run_id=run.id, candidate="GRE", status="PASS", metrics={})
        s.add(sample); s.flush()
        s.add(BenchmarkReceipt(sample_id=sample.id, document={"method_id": "GRE"}))
        old = Job(kind="benchmark", state="PASS", payload={"_run_id": run.id})
        new = Job(kind="benchmark", state="PENDING", payload={})
        s.add_all([old, new]); s.commit()
        old_id, new_id = old.id, new.id
    app = FastAPI()
    app.include_router(create_router(factory, lambda _: None, lambda _: None))
    client = TestClient(app)
    assert client.get(f"/benchmarks/{old_id}/results").json()["results"]
    assert client.get(f"/benchmarks/{new_id}/results").json()["results"] == []
    assert client.get(f"/benchmarks/{new_id}/receipts/GRE").status_code == 404


def test_unconfigured_production_executor_refuses_a_job_before_starting(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'app.db').as_posix()}")
    from apps.api import main
    monkeypatch.setattr(main, "_shared_factory", None)
    monkeypatch.setattr(main, "_shared_engine", None)
    client = TestClient(main.create_app())
    with main.session_factory() as s:
        before = s.query(Job).count()
    response = client.post("/benchmarks", json={"node_a": {"node_id": "a"},
                                                "node_b": {"node_id": "b"}, "profile": "QUICK"})
    assert response.status_code == 503
    with main.session_factory() as s:
        assert s.query(Job).count() == before
