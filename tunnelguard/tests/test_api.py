"""API tests — auth, CRUD, state, mode switching, settings guardrails."""
import pytest
from fastapi.testclient import TestClient


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


def auth(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "testpass"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


class TestAuth:
    def test_login_ok(self, client):
        h = auth(client)
        r = client.get("/api/me", headers=h)
        assert r.status_code == 200 and r.json()["username"] == "admin"

    def test_login_bad(self, client):
        r = client.post("/api/auth/login",
                        json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_protected_without_token(self, client):
        assert client.get("/api/state").status_code == 401

    def test_health_public(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200 and r.json()["ok"] is True


class TestTunnels:
    def test_crud(self, client):
        h = auth(client)
        r = client.post("/api/tunnels", headers=h, json={
            "name": "wg-main", "engine": "wireguard", "local_ip": "10.10.10.1",
            "remote_ip": "10.10.10.2", "mtu": 1420,
            "config": {"private_key": "A" * 44}})
        assert r.status_code == 200
        tid = r.json()["id"]
        r = client.get("/api/tunnels", headers=h)
        names = [x["name"] for x in r.json()["tunnels"]]
        assert "wg-main" in names and "primary" in names
        r = client.put(f"/api/tunnels/{tid}", headers=h, json={
            "name": "wg-renamed", "engine": "wireguard", "mtu": 1400, "config": {}})
        assert r.status_code == 200
        r = client.delete(f"/api/tunnels/{tid}", headers=h)
        assert r.status_code == 200

    def test_unknown_engine_rejected(self, client):
        h = auth(client)
        r = client.post("/api/tunnels", headers=h, json={
            "name": "x", "engine": "pptp"})
        assert r.status_code == 400

    def test_config_render_endpoint(self, client):
        h = auth(client)
        r = client.get("/api/tunnels/1/config", headers=h)
        assert r.status_code == 200
        assert "artifacts" in r.json()


class TestFailoverFlow:
    def test_mode_and_switch(self, client, sim_pair):
        h = auth(client)
        # seed: manual + pin tunnel 2
        r = client.post("/api/mode", headers=h,
                        json={"mode": "manual", "pinned_tunnel_id": sim_pair["t2"]})
        assert r.status_code == 200
        st = client.get("/api/state", headers=h).json()
        assert st["mode"] == "manual"
        assert st["active"]["id"] == sim_pair["t2"]
        # switch back to auto
        r = client.post("/api/mode", headers=h, json={"mode": "auto"})
        assert r.status_code == 200

    def test_switch_endpoint_creates_manual(self, client, sim_pair, fsm):
        h = auth(client)
        fsm.run_once()
        r = client.post(f"/api/failover/switch/{sim_pair['t2']}", headers=h)
        assert r.status_code == 200
        st = client.get("/api/state", headers=h).json()
        assert st["mode"] == "manual" and st["active"]["id"] == sim_pair["t2"]

    def test_metrics_and_events(self, client, sim_pair, fsm):
        h = auth(client)
        fsm.run_once()
        r = client.get("/api/metrics?range_s=900", headers=h)
        assert r.status_code == 200
        assert str(sim_pair["t1"]) in r.json()["series"]
        r = client.get("/api/events", headers=h)
        assert r.status_code == 200 and isinstance(r.json()["events"], list)


class TestSettingsGuard:
    def test_weights_sum_enforced(self, client):
        h = auth(client)
        r = client.put("/api/settings", headers=h, json={
            "patch": {"weight_loss": 90, "weight_latency": 90,
                      "weight_jitter": 90, "weight_stability": 90}})
        assert r.status_code == 400

    def test_flappy_threshold_rejected(self, client):
        h = auth(client)
        r = client.put("/api/settings", headers=h, json={"patch": {"cooldown_s": 2}})
        assert r.status_code == 400

    def test_valid_patch(self, client):
        h = auth(client)
        r = client.put("/api/settings", headers=h, json={"patch": {"cooldown_s": 90}})
        assert r.status_code == 200 and r.json()["cooldown_s"] == 90

    def test_admin_only(self, client):
        h = auth(client)  # role admin ok; anonymous forbidden checked elsewhere
        assert client.get("/api/settings").status_code == 401
