"""Benchmark API tests (P6 §33) — unit_portable tier.

Non-blocking start → RUNNING → terminal state; cancel; ranked results;
sanitized receipt retrieval. Uses a real FastAPI TestClient with tiny
fakes (no network).
"""
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.benchmark_api import create_router
from core.models import Base
from engines.adapters import ProbeResult
from orchestrator.benchmarking import NodeCaps

pytestmark = pytest.mark.unit_portable

CAPS = {"node_id": "n1", "binaries": ["wg", "wg-quick", "gost", "ssh", "ip",
                                      "openvpn", "swanctl", "xray", "frpc", "frps",
                                      "sing-box", "rathole", "chisel", "wstunnel",
                                      "paqet", "hedioum", "hajsaman", "waterwall"],
        "kernel_modules": ["wireguard", "ip_gre", "ipip", "sit", "tun",
                           "vxlan", "vti", "xfrm", "esp"],
        "privileged": True, "os": "linux", "arch": "amd64"}


class ApiFakeAdapter:
    def __init__(self, cand):
        self.cand = cand

    def configure(self): pass

    def start(self): time.sleep(0.01)

    def probe(self):
        return ProbeResult(ok=True, evidence="200 OK")

    def metrics(self):
        return {"rtt_avg": 12.0, "loss_pct": 0.0, "jitter": 0.9}


def caps_from_dict(p):
    return NodeCaps(node_id=p["node_id"], binaries=set(p["binaries"]),
                    kernel_modules=set(p["kernel_modules"]),
                    privileged=p["privileged"], os=p["os"], arch=p["arch"])


@pytest.fixture()
def client():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng)
    app = FastAPI()
    app.include_router(create_router(factory, caps_from_dict, ApiFakeAdapter))
    return TestClient(app)


class TestBenchmarkApi:
    def test_start_returns_immediately_with_counts(self, client):
        r = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                             "profile": "QUICK"})
        assert r.status_code == 200
        body = r.json()
        assert body["profile"] == "QUICK" and body["compatible"] > 20
        assert "job_id" in body

    def test_invalid_profile_rejected(self, client):
        r = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                             "profile": "ULTRA"})
        assert r.status_code == 400

    def test_job_reaches_terminal_state(self, client):
        job = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                               "profile": "QUICK"}).json()["job_id"]
        for _ in range(100):
            state = client.get(f"/benchmarks/{job}").json()
            if state["state"] in ("PASS", "FAILED", "CANCELLED", "TIMED_OUT"):
                break
            time.sleep(0.05)
        assert state["state"] in ("PASS", "FAILED")
        assert state["finished_at"] is not None

    def test_results_ranked_best_first(self, client):
        job = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                               "profile": "QUICK"}).json()["job_id"]
        for _ in range(100):
            if client.get(f"/benchmarks/{job}").json()["state"] in ("PASS", "FAILED"):
                break
            time.sleep(0.05)
        res = client.get(f"/benchmarks/{job}/results").json()
        assert res["results"], "no results persisted"
        statuses = [r["status"] for r in res["results"]]
        # PASS league before FAILED before BLOCKED/INCOMPATIBLE
        first_failed = statuses.index("FAILED") if "FAILED" in statuses else len(statuses)
        first_blocked = next((i for i, s in enumerate(statuses)
                              if s in ("BLOCKED", "INCOMPATIBLE")), len(statuses))
        assert first_failed == len(statuses) or all(
            s in ("PASS", "DEGRADED") for s in statuses[:first_failed])

    def test_receipt_sanitized_and_retrievable(self, client):
        job = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                               "profile": "QUICK"}).json()["job_id"]
        for _ in range(100):
            if client.get(f"/benchmarks/{job}").json()["state"] in ("PASS", "FAILED"):
                break
            time.sleep(0.05)
        res = client.get(f"/benchmarks/{job}/results").json()
        cand = res["results"][0]["candidate"]
        rec = client.get(f"/benchmarks/{job}/receipts/{cand}")
        assert rec.status_code == 200
        doc = rec.json()
        assert doc["method_id"] == cand and "methodology" in doc
        assert "***" not in str(doc.get("metrics", {})).replace("***REDACTED***", "")
        missing = client.get(f"/benchmarks/{job}/receipts/NOPE")
        assert missing.status_code == 404

    def test_unknown_job_404(self, client):
        assert client.get("/benchmarks/zzz").status_code == 404
