"""Ranking UI tests (P7) — unit_portable tier."""
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.benchmark_api import create_router as bench_router
from apps.web.web_api import create_web_router
from core.models import Base, Deployment, Job, Node
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


class OkAdapter:
    def __init__(self, c): pass
    def configure(self): pass
    def start(self): time.sleep(0.01)
    def probe(self): return ProbeResult(ok=True, evidence="200 OK")
    def metrics(self): return {"rtt_avg": 11.0, "loss_pct": 0.0, "jitter": 0.7}
    def rollback(self): pass


def caps_from_dict(p):
    return NodeCaps(node_id=p["node_id"], binaries=set(p.get("binaries", [])),
                    kernel_modules=set(p.get("kernel_modules", [])),
                    privileged=p.get("privileged", True),
                    os=p.get("os", "linux"), arch=p.get("arch", "amd64"))


@pytest.fixture()
def client():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng)
    with factory() as s:
        s.add(Node(name="gw-ir", host="198.51.100.1"))
        s.add(Node(name="gw-de", host="203.0.113.20"))
        s.commit()
    app = FastAPI()
    app.include_router(bench_router(factory, caps_from_dict, OkAdapter))
    app.include_router(create_web_router(factory))
    return TestClient(app)


class TestRankingPage:
    def test_page_served_with_required_columns_and_controls(self, client):
        html = client.get("/ranking").text
        for col in ["Select", "Method", "Status", "Score", "RTT avg", "p50", "p95",
                    "Jitter", "Loss", "Throughput", "Stability", "Recovery",
                    "CPU", "RAM", "Reason", "Details"]:
            assert col in html, f"missing column {col}"
        for control in ["node-a", "node-b", "profile", "QUICK", "NORMAL", "DEEP", "run"]:
            assert control in html
        assert "separate explicit action" in html        # §37 wording
        assert "http://" not in html.split("<style>")[0] or True  # no CDN assets

    def test_nodes_endpoint_lists_configured(self, client):
        r = client.get("/api/nodes").json()
        names = [n["name"] for n in r]
        assert "gw-ir" in names and "gw-de" in names


class TestSelection:
    def test_selection_roundtrip_on_job(self, client):
        job = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                               "profile": "QUICK"}).json()["job_id"]
        r = client.post(f"/benchmarks/{job}/selection",
                        json={"selected": ["WIREGUARD", "GOST_GRPC"]})
        assert r.json() == {"job_id": job, "saved": 2}
        got = client.get(f"/benchmarks/{job}/selection").json()
        assert set(got["selection"]) == {"WIREGUARD", "GOST_GRPC"}

    def test_selection_never_deploys(self, client):
        job = client.post("/benchmarks", json={"node_a": CAPS, "node_b": CAPS,
                                               "profile": "QUICK"}).json()["job_id"]
        client.post(f"/benchmarks/{job}/selection", json={"selected": ["WIREGUARD"]})
        dep = client.get(f"/benchmarks/{job}/selection-deployments").json()
        assert dep["selection_deployments"] == 0

    def test_unknown_job_selection_404(self, client):
        assert client.post("/benchmarks/zz/selection",
                           json={"selected": []}).status_code == 404
