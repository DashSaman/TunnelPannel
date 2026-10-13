"""Production wiring contracts: no legacy services, encrypted nodes, real IDs."""
import hashlib
import os
import subprocess
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Base, Node, SecretReference


def test_deployment_bodies_import_without_legacy_services():
    env = {k: v for k, v in os.environ.items() if k not in
           ("DATABASE_URL", "REDIS_URL", "APP_SECRET_KEY")}
    result = subprocess.run([sys.executable, "-c",
                             "from plan_executor.executor import deploy_kernel"],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.fixture
def nodes_api(tmp_path, monkeypatch):
    from apps.api.nodes_api import create_nodes_router
    monkeypatch.setenv("TP_SECRET_KEY", "installation-secret-for-test-only")
    monkeypatch.setenv("TP_RBAC_TOKENS", ",".join(
        role + ":" + hashlib.sha256(token.encode()).hexdigest()
        for role, token in [("SUPER_ADMIN", "admin-test"), ("VIEWER", "viewer-test")]))
    engine = create_engine(f"sqlite:///{tmp_path / 'nodes.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    app = FastAPI()
    app.include_router(create_nodes_router(factory))
    return TestClient(app), factory


NODE = {"name": "test-host", "host": "192.0.2.8", "ssh_username": "root",
        "password": "unique-test-password", "host_key_fingerprint": "a" * 64}
ADMIN = {"Authorization": "Bearer admin-test"}


def test_node_registration_encrypts_and_never_returns_credentials(nodes_api):
    client, factory = nodes_api
    response = client.post("/api/nodes", headers=ADMIN, json=NODE)
    assert response.status_code == 201, response.text
    assert "unique-test-password" not in response.text
    with factory() as s:
        node = s.query(Node).one()
        secret = s.get(SecretReference, node.secret_ref)
        assert "unique-test-password" not in secret.ciphertext
        from orchestrator.remote_nodes import decrypt_credentials
        assert decrypt_credentials(secret.ciphertext)["secret"] == NODE["password"]


@pytest.mark.parametrize("headers,status", [({}, 401),
    ({"Authorization": "Bearer viewer-test"}, 403)])
def test_node_registration_enforces_admin(nodes_api, headers, status):
    client, factory = nodes_api
    assert client.post("/api/nodes", headers=headers, json=NODE).status_code == status
    with factory() as s:
        assert s.query(Node).count() == 0


@pytest.mark.parametrize("changes", [{"host": "host; touch /tmp/injected"},
    {"host_key_fingerprint": ""}, {"ssh_username": "root;id"},
    {"password": "", "private_key": ""}, {"ssh_port": 70000}])
def test_node_registration_rejects_unsafe_inputs(nodes_api, changes):
    client, _ = nodes_api
    assert client.post("/api/nodes", headers=ADMIN, json={**NODE, **changes}).status_code == 422


def test_invalid_registration_does_not_echo_credentials(nodes_api):
    client, _ = nodes_api
    response = client.post('/api/nodes', headers=ADMIN,
                           json={**NODE, 'host_key_fingerprint': ''})
    assert response.status_code == 422
    assert NODE['password'] not in response.text


def test_node_list_is_sanitized(nodes_api):
    client, _ = nodes_api
    assert client.post("/api/nodes", headers=ADMIN, json=NODE).status_code == 201
    response = client.get("/api/nodes", headers=ADMIN)
    assert response.status_code == 200
    assert response.json()[0]["host"] == NODE["host"]
    assert "secret" not in response.text and "ciphertext" not in response.text


def test_node_credentials_can_be_rotated_without_changing_identity(nodes_api):
    client, factory = nodes_api
    created = client.post('/api/nodes', headers=ADMIN, json=NODE).json()
    updated = client.put('/api/nodes/' + created['id'], headers=ADMIN,
                         json={**NODE, 'password': 'rotated-test-password'})
    assert updated.status_code == 200
    assert updated.json()['id'] == created['id']
    assert 'rotated-test-password' not in updated.text
    from orchestrator.remote_nodes import node_access
    with factory() as session:
        _, credentials = node_access(session, created['id'])
        assert credentials['secret'] == 'rotated-test-password'
    assert client.put('/api/nodes/' + created['id'], headers=ADMIN,
                      json={**NODE, 'host': '192.0.2.9'}).status_code == 400


def test_rejects_key_mismatch_before_remote_commands():
    from orchestrator.remote_nodes import verify_host_key
    with pytest.raises(ValueError, match="host key"):
        verify_host_key("a" * 64, b"untrusted-host-key")


def test_failed_benchmark_cleanup_prevents_pass(tmp_path):
    from engines.adapters import ProbeResult
    from orchestrator.benchmarking import Candidate
    from orchestrator.benchmarking.runner import BenchmarkRunner
    engine = create_engine(f"sqlite:///{tmp_path / 'cleanup.db'}")
    Base.metadata.create_all(engine)
    class Adapter:
        def configure(self): pass
        def start(self): pass
        def probe(self): return ProbeResult(True, "real test seam")
        def metrics(self): return {}
        def rollback(self): raise RuntimeError("teardown denied")
    with sessionmaker(bind=engine)() as s:
        cand = Candidate("gre", "default", "GRE", "kernel", "COMPATIBLE")
        runner = BenchmarkRunner(s, "actual-a", "actual-b", "QUICK", lambda c: Adapter(), [cand])
        result = runner.run()
        assert result[0].status == "FAILED"
        from core.models import BenchmarkRun
        run = s.query(BenchmarkRun).one()
        assert (run.node_a, run.node_b) == ("actual-a", "actual-b")
