"""Security-hardening acceptance tests (P13 final gate item 1).

Proves, with running code: RBAC matrix (SUPER_ADMIN/OPERATOR/VIEWER),
read-only enforcement for VIEWER, unauthorized rejection, forbidden
privileged mutation rejection, AUDIT EVENTS for security-sensitive
mutations, ACTIVE rate limiting, secret redaction, no arbitrary-shell
endpoint, and no executor/paramiko exposure to untrusted API input.
"""
import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from core.models import AuditLog

pytestmark = pytest.mark.unit_portable


def _tok(role):
    return f"tok-{role}-secret"


def _hdr(role):
    return {"Authorization": f"Bearer {_tok(role)}"}


@pytest.fixture()
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'sec.db').as_posix()}")
    monkeypatch.delenv("TP_RATE_LIMIT", raising=False)
    raw = ",".join(
        f"{role}:{hashlib.sha256(_tok(role).encode()).hexdigest()}"
        for role in ("SUPER_ADMIN", "OPERATOR", "VIEWER"))
    monkeypatch.setenv("TP_RBAC_TOKENS", raw)
    import core.security as sec
    sec._limiters.clear()          # isolate sliding windows per test
    import importlib
    import apps.api.main as api_main
    importlib.reload(api_main)     # fresh engine bound to THIS test's DATABASE_URL
    app = api_main.create_app()
    app.state.api_main = api_main
    yield app
    sec._limiters.clear()


@pytest.fixture()
def client(app):
    return TestClient(app)


class TestRBACMatrix:
    def test_super_admin_permissions(self, client):
        r = client.post("/api/admin/reload", headers=_hdr("SUPER_ADMIN"))
        assert r.status_code == 200

    def test_operator_permissions(self, client):
        r = client.post("/api/admin/reload", headers=_hdr("OPERATOR"))
        assert r.status_code == 200

    def test_viewer_read_only_enforced(self, client):
        # viewer may read…
        assert client.get("/api/whoami", headers=_hdr("VIEWER")).status_code == 200
        # …but any privileged mutation is rejected server-side
        assert client.post("/api/admin/reload",
                           headers=_hdr("VIEWER")).status_code == 403

    def test_unauthorized_rejected(self, client):
        assert client.post("/api/admin/reload").status_code == 401
        assert client.post("/api/admin/reload",
                           headers={"Authorization": "Bearer nope"}).status_code == 401

    def test_forbidden_privileged_mutation_rejected(self, client):
        # a valid VIEWER token attempting an OPERATOR mutation
        r = client.post("/api/admin/reload", headers=_hdr("VIEWER"))
        assert r.status_code == 403 and "not authorized" in r.text


class TestAuditLog:
    def _db(self, app):
        from sqlalchemy.orm import Session
        return Session(app.state.api_main._shared_engine)

    def test_privileged_mutation_produces_audit_event(self, app, client):
        client.post("/api/admin/reload", headers=_hdr("OPERATOR"))
        with self._db(app) as s:
            rows = s.scalars(select(AuditLog)).all()
        assert any(r.action == "admin.reload" for r in rows)
        row = next(r for r in rows if r.action == "admin.reload")
        assert row.actor.startswith("OPERATOR:")           # redacted identity
        assert "tok-OPERATOR-secret" not in row.actor      # no raw token

    def test_failed_mutation_not_audited_as_success(self, app, client):
        client.post("/api/admin/reload", headers=_hdr("VIEWER"))    # 403
        with self._db(app) as s:
            rows = s.scalars(select(AuditLog)).all()
        assert all(r.action != "admin.reload" for r in rows)

    def test_failover_group_create_audited(self, app, client):
        client.post("/failover-groups", headers=_hdr("OPERATOR"), json={
            "name": "audit-check",
            "members": [{"candidate": "WIREGUARD", "priority": 1}]})
        with self._db(app) as s:
            rows = s.scalars(select(AuditLog)).all()
        assert any(r.action == "failover.group_create" and r.target == "audit-check"
                   for r in rows)


class TestRateLimiting:
    def test_rate_limit_genuinely_active(self, app, client):
        codes = [client.post("/api/admin/reload", headers=_hdr("OPERATOR")).status_code
                 for _ in range(10)]
        assert codes[:6] == [200] * 6                        # within limit
        assert 429 in codes[6:]                              # throttled after

    def test_rate_limit_isolated_per_identity(self, app, client):
        for _ in range(6):
            client.post("/api/admin/reload", headers=_hdr("OPERATOR"))
        # different identity is NOT punished by the operator's burst
        assert client.post("/api/admin/reload",
                           headers=_hdr("SUPER_ADMIN")).status_code == 200

    def test_rate_limit_explicit_disable_switch(self, app, client, monkeypatch):
        monkeypatch.setenv("TP_RATE_LIMIT", "0")
        codes = [client.post("/api/admin/reload", headers=_hdr("OPERATOR")).status_code
                 for _ in range(10)]
        assert codes == [200] * 10                           # dev mode off-switch


class TestSurfaceHardening:
    def test_no_arbitrary_shell_endpoint(self, app):
        paths = {getattr(r, "path", "") for r in app.routes}
        for forbidden in ("/api/exec", "/api/run", "/api/shell", "/api/cmd",
                          "/api/ssh", "/api/execute"):
            assert forbidden not in paths

    def test_executors_not_importable_from_api_input(self):
        """The API layer never constructs executors; engines own them.
        Static proof: no apps/ module references paramiko/SSHExecutor."""
        import pathlib, re
        bad = []
        for p in pathlib.Path("apps").rglob("*.py"):
            src = p.read_text(encoding="utf-8")
            if re.search(r"paramiko|SSHExecutor|LocalExecutor", src):
                bad.append(str(p))
        assert bad == []

    def test_secret_redaction_utility(self):
        from apps.bot.core import redact
        leaked = "password=hunter2 token=ghp_" + "A" * 30
        out = redact(leaked)
        assert "hunter2" not in out and "ghp_" not in out
