"""Canonical app + RBAC tests (P13 §33, §34) — unit_portable tier."""
import hashlib

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.unit_portable


def _set_tokens(monkeypatch, tokens: dict[str, str]):
    """tokens: role -> plain token; stored as sha256 hashes."""
    raw = ",".join(f"{role}:{hashlib.sha256(tok.encode()).hexdigest()}"
                   for role, tok in tokens.items())
    monkeypatch.setenv("TP_RBAC_TOKENS", raw)


@pytest.fixture()
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'app.db').as_posix()}")
    from apps.api.main import create_app
    return create_app()


class TestHealthAndSurface:
    def test_health_ok(self, app):
        c = TestClient(app)
        assert c.get("/health").json()["ok"] is True

    def test_status_and_metrics(self, app):
        c = TestClient(app)
        s = c.get("/api/status").json()
        assert {"nodes", "failover_groups", "active_alerts"} <= set(s)
        metrics = c.get("/metrics").text
        assert "tunnelpannel_nodes_total" in metrics

    def test_ranking_and_topology_pages_served(self, app):
        c = TestClient(app)
        assert "Benchmark" in c.get("/ranking").text
        assert "Topology" in c.get("/topology").text


class TestRBAC:
    def test_no_token_401(self, app):
        c = TestClient(app)
        assert c.get("/api/whoami").status_code == 401

    def test_invalid_token_401(self, app, monkeypatch):
        _set_tokens(monkeypatch, {"VIEWER": "viewer-tok"})
        c = TestClient(app)
        assert c.get("/api/whoami",
                     headers={"Authorization": "Bearer wrong"}).status_code == 401

    def test_viewer_cannot_admin_reload(self, app, monkeypatch):
        _set_tokens(monkeypatch, {"VIEWER": "viewer-tok", "OPERATOR": "op-tok"})
        c = TestClient(app)
        r = c.post("/api/admin/reload",
                   headers={"Authorization": "Bearer viewer-tok"})
        assert r.status_code == 403                       # negative authorization

    def test_operator_can_reload(self, app, monkeypatch):
        _set_tokens(monkeypatch, {"OPERATOR": "op-tok"})
        c = TestClient(app)
        r = c.post("/api/admin/reload",
                   headers={"Authorization": "Bearer op-tok"})
        assert r.status_code == 200

    def test_viewer_can_view(self, app, monkeypatch):
        _set_tokens(monkeypatch, {"VIEWER": "viewer-tok"})
        c = TestClient(app)
        r = c.get("/api/whoami", headers={"Authorization": "Bearer viewer-tok"})
        assert r.status_code == 200 and r.json()["role"] == "VIEWER"

    def test_token_never_echoed(self, app, monkeypatch):
        _set_tokens(monkeypatch, {"VIEWER": "super-secret-tok"})
        c = TestClient(app)
        body = c.get("/api/whoami",
                     headers={"Authorization": "Bearer super-secret-tok"}).text
        assert "super-secret-tok" not in body


class TestPrivilegeSeparation:
    def test_no_raw_shell_endpoint_in_api_surface(self, app):
        """§34: the public API must not expose arbitrary command execution."""
        c = TestClient(app)
        paths = {r.path for r in app.routes}
        for forbidden in ("/api/exec", "/api/run", "/api/shell", "/api/cmd"):
            assert forbidden not in paths
        # every route is structured; none accepts raw command bodies
        for route in app.routes:
            assert "command" not in getattr(route, "path", "")


class TestPermissions:
    def test_permission_map(self):
        from core.security import allowed
        assert allowed("VIEWER", "view") and not allowed("VIEWER", "operate_network")
        assert allowed("OPERATOR", "operate_network")
        assert not allowed("OPERATOR", "manage_users")
        assert allowed("SUPER_ADMIN", "manage_users")
