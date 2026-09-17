"""Wizard endpoints: batch create + auto-activation pipeline.

These run in sim_mode so activation exercises the FULL API path
(create -> precheck -> engine up -> status -> first probe) without
touching host networking. The routing-capability guard is tested
against a SOCKS-only hedioum tunnel (sim-mode sim adapter exposes no
routing_capable, so we drive the FSM guard directly with a stub).
"""
import json

import pytest
from fastapi.testclient import TestClient

from tests.test_api import auth  # reuse login helper


@pytest.fixture()
def client(fresh_db, sim_pair):
    from tfd import db as dbm, security
    from tfd.api import app
    with dbm.tx() as d:
        d.execute("DELETE FROM users")
        d.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)",
                  ("admin", security.hash_password("testpass"), "admin", 1.0))
    dbm.set_settings({"sim_mode": True})
    return TestClient(app)


class TestBatch:
    def test_batch_activate_sim(self, client):
        h = auth(client)
        r = client.post("/api/tunnels/batch", headers=h, json={
            "tunnels": [
                {"name": "wg-1", "engine": "sim", "mtu": 1420,
                 "config": {"base_rtt_ms": 30, "jitter_ms": 3}},
                {"name": "wg-2", "engine": "sim", "mtu": 1420,
                 "config": {"base_rtt_ms": 60, "jitter_ms": 5}},
                {"name": "hed-1", "engine": "sim", "mtu": 1500,
                 "config": {"base_rtt_ms": 90, "jitter_ms": 8}},
            ],
            "activate": True, "verify": True})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 3 and data["ok"] == 3
        for res in data["results"]:
            assert res["ok"] is True, res
            steps = {s["step"] for s in res["steps"]}
            assert {"precheck", "engine_up", "status_check",
                    "first_probe"} <= steps

    def test_batch_without_activation(self, client):
        h = auth(client)
        r = client.post("/api/tunnels/batch", headers=h, json={
            "tunnels": [{"name": "lazy", "engine": "sim", "config": {}}],
            "activate": False})
        data = r.json()
        assert data["ok"] == 1
        assert data["results"][0]["steps"] == [{"step": "created", "ok": True}]
        # engine was never started
        assert data["results"][0]["id"]

    def test_batch_rejects_unknown_engine(self, client):
        h = auth(client)
        r = client.post("/api/tunnels/batch", headers=h, json={
            "tunnels": [{"name": "bad", "engine": "nope", "config": {}}]})
        data = r.json()
        assert data["ok"] == 0
        assert "unknown engine" in data["results"][0]["error"]

    def test_batch_cap_12(self, client):
        h = auth(client)
        r = client.post("/api/tunnels/batch", headers=h, json={
            "tunnels": [{"name": f"t{i}", "engine": "sim", "config": {}}
                        for i in range(13)]})
        assert r.status_code == 400


class TestActivateSingle:
    def test_activate_and_steps(self, client):
        h = auth(client)
        tid = client.post("/api/tunnels", headers=h, json={
            "name": "single", "engine": "sim",
            "config": {"base_rtt_ms": 50}}).json()["id"]
        r = client.post(f"/api/tunnels/{tid}/activate", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert {s["step"] for s in data["steps"]} >= {"precheck", "engine_up"}

    def test_activate_404(self, client):
        h = auth(client)
        assert client.post("/api/tunnels/9999/activate",
                           headers=h).status_code == 404


class TestRoutingGuard:
    def test_socks_only_tunnel_never_active(self, fresh_db):
        """A SOCKS-only hedioum tunnel (routing_capable=False) must never be
        promoted to ACTIVE. Production mode (sim off), hedioum adapter real,
        so the FSM routing guard actually runs."""
        from tfd import db as dbm
        from tfd.failover import engine
        from tfd.engines.hedioum import HedioumAdapter

        dbm.set_settings({"sim_mode": False})
        tid = dbm.db().execute(
            "INSERT INTO tunnels(name,engine,iface,local_ip,remote_ip,remote_host,"
            "mtu,config,remote_ssh,enabled,priority,created_at) "
            "VALUES('hed-socks','hedioum','hed0',NULL,NULL,'203.0.113.5',1500,?,'{}',1,1,1.0)",
            (json.dumps({"socks_port": 41555, "tun_enabled": False}),)
        ).lastrowid
        dbm.db().commit()
        assert HedioumAdapter(dbm.get_tunnel(tid)).routing_capable is False
        with engine._lock:
            engine._streaks.clear()
            engine._switches.clear()
        out = engine.run_once()
        # probe fails (nothing listens on 41555) but streak < threshold:
        # the honest 'probes pass yet not routable / holding' branch
        assert out["action"] == "hold"
        assert dbm.get_state()["active_tunnel_id"] != tid

        # with TUN enabled the same tunnel IS routing-capable
        dbm.db().execute("UPDATE tunnels SET config=? WHERE id=?",
                         (json.dumps({"socks_port": 41555,
                                      "tun_enabled": True}), tid))
        dbm.db().commit()
        assert HedioumAdapter(dbm.get_tunnel(tid)).routing_capable is True
