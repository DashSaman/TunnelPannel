"""Failover API tests (P10 §58 API side) — unit_portable tier."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.failover_api import create_router
from core.models import Base, Event, FailoverMember

pytestmark = pytest.mark.unit_portable


@pytest.fixture()
def client():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng)
    app = FastAPI()
    app.include_router(create_router(factory))
    c = TestClient(app)
    c.test_engine = eng
    return c


MEMBERS = [
    {"candidate": "WIREGUARD", "priority": 1},
    {"candidate": "GOST_GRPC", "priority": 2},
    {"candidate": "chain:gre-over-wg", "priority": 3, "kind": "chain"},
]


class TestGroupLifecycle:
    def test_create_group_with_members(self, client):
        r = client.post("/failover-groups", json={"name": "edge", "members": MEMBERS})
        assert r.status_code == 200
        body = r.json()
        assert body["active"] == "m0"                      # priority 1 first
        with client.test_engine.connect() as conn:
            n = len(conn.execute(select(FailoverMember)).all())
        assert n == 3

    def test_duplicate_priorities_rejected(self, client):
        r = client.post("/failover-groups", json={
            "name": "x", "members": [{"candidate": "A", "priority": 1},
                                     {"candidate": "B", "priority": 1}]})
        assert r.status_code == 400

    def test_empty_group_rejected(self, client):
        assert client.post("/failover-groups",
                           json={"name": "x", "members": []}).status_code == 400

    def test_diversity_exposed_on_create(self, client):
        r = client.post("/failover-groups", json={"name": "d", "members": [
            {"candidate": "WIREGUARD", "priority": 1},
            {"candidate": "GRE", "priority": 2}]})
        body = r.json()
        assert "diversity_recommendation" in body


class TestProbeFlow:
    def make_group(self, client):
        return client.post("/failover-groups",
                           json={"name": "g", "members": MEMBERS,
                                 "failure_threshold": 2,
                                 "cooldown_s": 0}).json()["group_id"]

    def test_probe_failure_switches_and_records_event(self, client):
        gid = self.make_group(client)
        for _ in range(2):
            r = client.post(f"/failover-groups/{gid}/probes",
                            json={"member_index": 0, "ok": False}).json()
        assert r["active"] == "m1"
        assert r["switch"] and r["switch"]["to"] == "m1"
        with client.test_engine.connect() as conn:
            events = conn.execute(select(Event)).all()
        assert any("switch m0 -> m1" in e.message for e in events)

    def test_single_failed_probe_no_switch(self, client):
        gid = self.make_group(client)
        r = client.post(f"/failover-groups/{gid}/probes",
                        json={"member_index": 0, "ok": False}).json()
        assert r["switch"] is None and r["active"] == "m0"

    def test_pin_and_release(self, client):
        gid = self.make_group(client)
        assert client.post(f"/failover-groups/{gid}/pin",
                           json={"member_index": 2}).json()["pinned"] == "m2"
        for _ in range(3):
            r = client.post(f"/failover-groups/{gid}/probes",
                            json={"member_index": 2, "ok": False}).json()
        assert r["active"] == "m2"                        # pin holds
        client.post(f"/failover-groups/{gid}/pin", json={"member_index": None})
        r = client.post(f"/failover-groups/{gid}/probes",
                        json={"member_index": 2, "ok": False}).json()
        # released + failing: leaves the pinned member
        assert r["active"] != "m2"

    def test_maintenance_moves_off(self, client):
        gid = self.make_group(client)
        r = client.post(f"/failover-groups/{gid}/maintenance",
                        json={"member_index": 0, "on": True}).json()
        assert r["switch"] and r["switch"]["to"] == "m1"

    def test_history_records_switches(self, client):
        gid = self.make_group(client)
        for _ in range(2):
            client.post(f"/failover-groups/{gid}/probes",
                        json={"member_index": 0, "ok": False})
        h = client.get(f"/failover-groups/{gid}/history").json()
        assert len(h["switches"]) == 1
        assert h["switches"][0]["actor"] in ("AUTO", "EMERGENCY")

    def test_unknown_group_404(self, client):
        assert client.get("/failover-groups/zz").status_code == 404
