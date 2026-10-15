import hashlib
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import BenchmarkReceipt, BenchmarkSample, Job, Node, NodeInventory
from orchestrator.benchmarking import Candidate, NodeCaps
from engines.adapters import ProbeResult

pytestmark = pytest.mark.unit_portable
HEADERS = {"Authorization": "Bearer mesh-test-owner"}


class FakeMeasuredAdapter:
    def configure(self): pass
    def start(self): pass
    def probe(self): return ProbeResult(True, "unit fixture only")
    def metrics(self):
        return {"rtt_avg": 2, "jitter": .1, "loss_pct": 0, "throughput_mbps": 80,
                "reconnect_s": .2, "recovery_ok": True, "rtt_basis": "http_request"}
    def rollback(self): pass


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'unused.db'}")
    monkeypatch.setenv("TP_WORKSPACES_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("TP_RBAC_TOKENS", "SUPER_ADMIN:" + hashlib.sha256(b"mesh-test-owner").hexdigest())
    from apps.api.main import create_app
    factory = sessionmaker(bind=create_engine(f"sqlite:///{tmp_path / 'system.db'}"))
    app = create_app(factory)
    with factory() as s:
        for index, node_id in enumerate(["ir", "de", "us"]):
            s.add(Node(id=node_id, name=node_id, host=f"8.8.8.{index + 1}",
                       host_key_fingerprint=str(index + 1) * 64))
            s.add(NodeInventory(node_id=node_id, snapshot={"os": "linux"}))
        s.commit()
    return TestClient(app), factory, app


def fake_prepare(req):
    candidates = [Candidate("wireguard", "default", "WIREGUARD", "VPN", "COMPATIBLE")]
    return (NodeCaps(req.node_a["node_id"]), NodeCaps(req.node_b["node_id"]),
            candidates, lambda _: FakeMeasuredAdapter())


def test_campaign_executes_all_pairs_records_receipts_and_manual_selection(panel):
    client, factory, app = panel
    app.state.mesh_campaigns.prepare = fake_prepare
    response = client.post("/api/mesh/campaigns", headers=HEADERS,
                           json={"nodes": ["ir", "de", "us"], "methods": ["WIREGUARD"]})
    assert response.status_code == 202, response.text
    campaign_id = response.json()["id"]
    for _ in range(150):
        state = client.get(f"/api/mesh/campaigns/{campaign_id}", headers=HEADERS).json()
        if state["state"] in {"PASS", "FAILED", "CANCELLED"}:
            break
        time.sleep(.03)
    assert state["state"] == "PASS", state
    assert len(state["routes"]) == 6
    assert all(route["recommendation"]["selected"] == ["WIREGUARD"] for route in state["routes"])
    assert all(route["recommendation"]["shortfall"] == 4 for route in state["routes"])
    route_id = state["routes"][0]["id"]
    url = f"/api/mesh/campaigns/{campaign_id}/routes/{route_id}/selection"
    assert client.put(url, headers=HEADERS, json={"methods": ["WIREGUARD"]}).status_code == 200
    assert client.put(url, headers=HEADERS, json={"methods": ["GRE"]}).status_code == 400
    with factory() as s:
        assert s.query(BenchmarkSample).count() == 6
        assert s.query(BenchmarkReceipt).count() == 6


def test_campaign_rejects_unknown_node_and_quick_profile(panel):
    client, _, _ = panel
    assert client.post("/api/mesh/campaigns", headers=HEADERS,
                       json={"nodes": ["ir", "missing"]}).status_code == 400
    assert client.post("/api/mesh/campaigns", headers=HEADERS,
                       json={"nodes": ["ir", "de"], "profile": "QUICK"}).status_code == 422


def test_customer_cannot_read_cancel_or_select_owner_campaign(panel):
    client, factory, _ = panel
    with factory() as s:
        job = Job(id="owner-job", kind="mesh_campaign", state="QUEUED", payload={"routes": []})
        s.add(job)
        s.commit()
    account = client.post("/api/workspaces", headers=HEADERS, json={"name": "Other"}).json()
    headers = {"Authorization": "Bearer " + account["api_key"]}
    assert client.get("/api/mesh/campaigns/owner-job", headers=headers).status_code == 404
    assert client.post("/api/mesh/campaigns/owner-job/cancel", headers=headers).status_code == 404
    assert client.put("/api/mesh/campaigns/owner-job/routes/x/selection", headers=headers,
                      json={"methods": ["WIREGUARD"]}).status_code == 404
