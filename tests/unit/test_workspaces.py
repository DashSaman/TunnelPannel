"""Customer boundaries are enforced on existing APIs, not just new mesh routes."""
import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.unit_portable
OWNER = {"Authorization": "Bearer owner-test-key"}


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'unused.db'}")
    monkeypatch.setenv("TP_WORKSPACES_DIR", str(tmp_path / "customers"))
    monkeypatch.setenv("TP_SECRET_KEY", "workspace-test-installation-secret")
    monkeypatch.setenv("TP_RBAC_TOKENS", "SUPER_ADMIN:" + hashlib.sha256(b"owner-test-key").hexdigest())
    from apps.api.main import create_app
    factory = sessionmaker(bind=create_engine(f"sqlite:///{tmp_path / 'system.db'}"))
    return TestClient(create_app(factory)), factory


def customer(client, name):
    response = client.post("/api/workspaces", headers=OWNER, json={"name": name})
    assert response.status_code == 201, response.text
    body = response.json()
    return body, {"Authorization": "Bearer " + body["api_key"]}


def test_separate_databases_cover_legacy_nodes_jobs_and_status(panel):
    client, _ = panel
    a, ah = customer(client, "Alice")
    b, bh = customer(client, "Bob")
    node = {"name": "edge", "host": "8.8.8.8", "password": "test-node-password",
            "host_key_fingerprint": "a" * 64}
    assert client.post("/api/nodes", headers=ah, json=node).status_code == 201
    assert client.get("/api/nodes", headers=bh).json() == []
    assert client.get("/api/nodes", headers=OWNER).json() == []
    assert client.get("/api/status", headers=ah).json()["nodes"] == 1
    assert client.get("/api/status", headers=bh).json()["nodes"] == 0
    assert client.get("/api/whoami", headers=ah).json()["workspace_id"] == a["id"]
    # Selecting a different workspace with a guessed ID cannot change scope.
    spoofed = {**ah, "X-Workspace-ID": b["id"]}
    assert len(client.get("/api/nodes", headers=spoofed).json()) == 1
    response = client.get("/api/workspaces", headers=ah)
    assert response.status_code == 403
    listing = client.get("/api/workspaces", headers=OWNER)
    assert a["api_key"] not in listing.text and b["api_key"] not in listing.text


def test_missing_token_cannot_read_or_mutate_old_unprotected_routes(panel):
    client, _ = panel
    for path in ("/api/status", "/api/alerts/active", "/metrics", "/api/topology"):
        assert client.get(path).status_code == 401, path
    assert client.post("/benchmarks/unknown/selection", json={"selected": []}).status_code == 401
    assert client.get("/health").status_code == 200


def test_revocation_and_customer_private_targets(panel):
    client, _ = panel
    account, headers = customer(client, "Revoked")
    node = {"name": "internal", "host": "127.0.0.1", "password": "test-node-password",
            "host_key_fingerprint": "a" * 64}
    assert client.post("/api/nodes", headers=headers, json=node).status_code == 400
    assert client.post(f"/api/workspaces/{account['id']}/disable", headers=OWNER).status_code == 200
    assert client.get("/api/nodes", headers=headers).status_code == 401


def test_customer_limit_is_enforced_by_existing_node_registration(panel):
    client, _ = panel
    response = client.post("/api/workspaces", headers=OWNER,
                           json={"name": "Small", "limits": {"max_nodes": 1}})
    assert response.status_code == 201, response.text
    headers = {"Authorization": "Bearer " + response.json()["api_key"]}
    node = {"name": "first", "host": "8.8.8.8", "password": "test-node-password",
            "host_key_fingerprint": "a" * 64}
    assert client.post("/api/nodes", headers=headers, json=node).status_code == 201
    assert client.post("/api/nodes", headers=headers, json={**node, "name": "second"}).status_code == 409


def test_factory_freeze_keeps_scope_after_request_context_is_reset(tmp_path):
    from core.workspaces import ScopedFactory, workspace_context
    system = sessionmaker(bind=create_engine(f"sqlite:///{tmp_path / 'system.db'}"))
    customer_factory = sessionmaker(bind=create_engine(f"sqlite:///{tmp_path / 'customer.db'}"))
    scoped = ScopedFactory(system)
    token = workspace_context.set({"factory": customer_factory, "id": "alice"})
    frozen = scoped.freeze()
    workspace_context.reset(token)
    assert frozen.kw["bind"] is customer_factory.kw["bind"]
    assert scoped.freeze().kw["bind"] is system.kw["bind"]


def test_owner_can_change_entitlements_and_rotate_key_without_exposing_old_key(panel):
    client, _ = panel
    account, headers = customer(client, 'Growing customer')
    path = '/api/workspaces/' + account['id']
    result = client.patch(path, headers=OWNER, json={'limits': {'max_tunnels_per_route': 8}})
    assert result.status_code == 200, result.text
    assert result.json()['limits']['max_tunnels_per_route'] == 8
    assert client.get('/api/mesh/config', headers=headers).json()['limits']['max_tunnels_per_route'] == 8
    rotated = client.post(path + '/rotate-key', headers=OWNER)
    assert rotated.status_code == 200, rotated.text
    fresh = {'Authorization': 'Bearer ' + rotated.json()['api_key']}
    assert client.get('/api/nodes', headers=headers).status_code == 401
    assert client.get('/api/nodes', headers=fresh).status_code == 200
    assert client.patch(path, headers=fresh, json={'enabled': False}).status_code == 403
    assert client.patch(path, headers=OWNER, json={'limits': {'unexpected_limit': 1}}).status_code == 400
