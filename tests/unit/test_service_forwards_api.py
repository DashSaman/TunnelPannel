"""Real auth/workspace middleware with an owned control-plane node seam."""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from core.workspaces import DEFAULT_LIMITS
from test_service_forward_lifecycle import ROUTE, body, control  # noqa: F401

pytestmark = pytest.mark.unit_portable
OWNER = {'Authorization': 'Bearer service-api-owner'}


@pytest.fixture
def services_api(control, tmp_path, monkeypatch):
    _, factory, nodes, _ = control
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(tmp_path / 'unused.db'))
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path / 'customers'))
    monkeypatch.setenv('TP_RBAC_TOKENS', 'SUPER_ADMIN:' + hashlib.sha256(b'service-api-owner').hexdigest())
    from apps.api.main import create_app
    app = create_app(factory)
    service = app.state.mesh_services
    service.nodes = nodes
    monkeypatch.setattr(service, 'kick', lambda *args: None)
    client = TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 12345))
    return client, factory, app


def admitted(client, **changes):
    value = body(**changes)
    ticket = client.post('/api/mesh/services/preflight', headers=OWNER, json=value)
    assert ticket.status_code == 200, ticket.text
    request = {**value, 'request_id': '1' * 32, 'preflight_id': ticket.json()['id'],
               'preflight_token': ticket.json()['token']}
    response = client.post('/api/mesh/services', headers=OWNER, json=request)
    assert response.status_code == 202, response.text
    return response.json()['id'], request


def test_authenticated_service_crud_replay_and_private_projection(services_api):
    client, factory, app = services_api
    assert app.state.mesh_routes.forward_dependencies is app.state.mesh_services
    assert client.get('/api/mesh/services').status_code == 401
    identity, request = admitted(client)
    assert client.post('/api/mesh/services', headers=OWNER, json=request).json()['id'] == identity
    app.state.mesh_services._run(factory, identity)
    response = client.get('/api/mesh/services/' + identity, headers=OWNER)
    assert response.status_code == 200 and response.json()['observed']
    assert response.json()['inherited']['rate_mbps'] == 32
    assert 'no-store' in response.headers.get('cache-control', '')
    for secret in ('runtime_secret_id', 'existing-private-gateway-password', 'fixture-ssh-password', '/etc/', '/opt/'):
        assert secret not in response.text
    history = client.get('/api/mesh/services', headers=OWNER)
    assert [item['id'] for item in history.json()] == [identity]
    assert client.request('DELETE', '/api/mesh/services/' + identity, headers=OWNER, json={'route_id': ROUTE}).status_code == 422
    assert client.delete('/api/mesh/services/' + identity, headers=OWNER).status_code == 202
    app.state.mesh_services._run(factory, identity)
    assert client.get('/api/mesh/services/' + identity, headers=OWNER).json()['state'] == 'STOPPED'


def test_schema_roles_and_cross_workspace_guards_cover_service_namespace(services_api, monkeypatch):
    client, _, app = services_api
    identity, _ = admitted(client)
    assert client.post('/api/mesh/services/preflight', headers=OWNER, json={**body(), 'workspace_id': 'f' * 32}).status_code == 422
    assert client.post('/api/mesh/services/preflight', headers=OWNER, json=body(bind_port=True)).status_code == 422
    monkeypatch.setenv('TP_RBAC_TOKENS', 'SUPER_ADMIN:' + hashlib.sha256(b'service-api-owner').hexdigest()
                       + ',VIEWER:' + hashlib.sha256(b'service-viewer').hexdigest())
    viewer = {'Authorization': 'Bearer service-viewer'}
    assert client.get('/api/mesh/services', headers=viewer).status_code == 200
    assert client.post('/api/mesh/services/preflight', headers=viewer, json=body()).status_code == 403
    customer = client.post('/api/workspaces', headers=OWNER, json={'name': 'Other customer'}).json()
    headers = {'Authorization': 'Bearer ' + customer['api_key']}
    assert client.get('/api/mesh/services', headers=headers).json() == []
    assert client.get('/api/mesh/services/' + identity, headers=headers).status_code == 404
    assert client.delete('/api/mesh/services/' + identity, headers=headers).status_code == 404
    assert client.get('/api/accounts', headers=headers).status_code == 403
    assert app.state.mesh_services.nodes.applies == 0


def test_service_edit_and_recovery_accept_only_strict_revision_bound_proofs(services_api):
    client, factory, app = services_api
    identity, _ = admitted(client)
    app.state.mesh_services._run(factory, identity)
    value = body(target_port=4950)
    ticket = client.post('/api/mesh/services/preflight', headers=OWNER,
        json={**value, 'service_id': identity, 'expected_revision': 1}).json()
    request = {**value, 'request_id': '2' * 32, 'preflight_id': ticket['id'],
               'preflight_token': ticket['token'], 'expected_revision': 1}
    path = '/api/mesh/services/' + identity
    assert client.put(path, headers=OWNER, json={**request, 'expected_revision': 2}).status_code == 409
    assert client.put(path, headers=OWNER, json=request).status_code == 202
    app.state.mesh_services.recover(factory)
    assert client.post(path + '/reconcile', headers=OWNER, json=request).status_code == 409
    ticket = client.post('/api/mesh/services/preflight', headers=OWNER,
        json={**value, 'service_id': identity, 'expected_revision': 1}).json()
    request.update(request_id='3' * 32, preflight_id=ticket['id'], preflight_token=ticket['token'])
    assert client.post(path + '/reconcile', headers=OWNER, json=request).status_code == 202
    app.state.mesh_services._run(factory, identity)
    result = client.get(path, headers=OWNER).json()
    assert result['revision'] == 2 and result['target_port'] == 4950
    assert 'password' not in json.dumps(result)


def test_cookie_service_mutation_requires_csrf_and_expired_customer_can_only_stop(services_api):
    from core.models import Job
    client, _, app = services_api
    customer = client.post('/api/workspaces', headers=OWNER, json={'name': 'Cookie customer'}).json()
    app.state.subscriptions.status = lambda identity, *args: {'can_start_work': False, 'limits': dict(DEFAULT_LIMITS)}
    headers = {'Authorization': 'Bearer ' + customer['api_key']}
    assert client.post('/api/mesh/services/preflight', headers=headers, json=body()).status_code == 402
    assert client.delete('/api/mesh/services/' + 'f' * 32, headers=headers).status_code == 404
    assert client.delete('/api/mesh/services/' + 'f' * 32 + '/reconcile', headers=headers).status_code == 402
    # Boundary-only queued intent: no source worker is started by this fixture.
    own = 'e' * 32
    scoped = app.state.workspace_registry._factory(customer['id'])
    with scoped() as session:
        session.add(Job(id=own, kind='mesh_service_forward', state='APPLYING',
                        payload={'workspace_id': customer['id'], 'route_id': ROUTE}))
        session.commit()
    assert client.delete('/api/mesh/services/' + own, headers=headers).status_code == 202
    with scoped() as session:
        assert session.get(Job, own).state == 'STOPPING'
    assert client.delete('/api/mesh/services/' + own, headers=OWNER).status_code == 404
    # Invitation/login use the existing account system, not a second service auth.
    invite = client.post('/api/accounts/invitations', headers=OWNER, json={
        'workspace_id': customer['id'], 'email': 'forward@example.test', 'role': 'OPERATOR'}).json()
    origin = {'Origin': 'http://127.0.0.1'}
    assert client.post('/auth/register', headers=origin, json={'invitation': invite['token'],
        'email': 'forward@example.test', 'password': 'long-local-service-cookie-password'}).status_code == 201
    login = client.post('/auth/login', headers=origin, json={
        'email': 'forward@example.test', 'password': 'long-local-service-cookie-password'})
    assert login.status_code == 200
    assert client.delete('/api/mesh/services/' + 'f' * 32, headers=origin).status_code == 403
    assert client.delete('/api/mesh/services/' + 'f' * 32,
        headers={**origin, 'X-CSRF-Token': login.json()['csrf']}).status_code == 404


def test_new_api_instance_adopts_same_owned_worker_and_operation_without_apply(services_api, monkeypatch):
    from apps.api.main import create_app
    from core.models import Job
    client, factory, app = services_api
    identity, _ = admitted(client)
    app.state.mesh_services._run(factory, identity)
    before = client.get('/api/mesh/services/' + identity, headers=OWNER).json()
    nodes = app.state.mesh_services.nodes
    with factory() as session:
        row = session.get(Job, identity)
        operation = dict(row.payload['operation'])
        row.state = 'APPLYING'  # Source was activated; controller lost its commit.
        session.commit()
    restarted = create_app(factory)
    restarted.state.mesh_services.nodes = nodes
    monkeypatch.setattr(restarted.state.mesh_services, 'kick', lambda *args: None)
    restarted.state.mesh_services.recover(factory)
    other = TestClient(restarted, base_url='http://127.0.0.1', client=('127.0.0.1', 12345))
    after = other.get('/api/mesh/services/' + identity, headers=OWNER).json()
    assert nodes.applies == 1 and after['state'] == 'ACTIVE'
    assert after['runtime']['worker_pid'] == before['runtime']['worker_pid']
    with factory() as session:
        assert session.get(Job, identity).payload['operation'] == operation


def test_public_observation_sanitizes_node_failure_and_preserves_parent(services_api, monkeypatch):
    from core.models import Job
    client, factory, app = services_api
    identity, _ = admitted(client)
    with factory() as session:
        before = dict(session.get(Job, ROUTE).payload)
    def unavailable(*args):
        raise RuntimeError('private-ssh-secret /root/private/operator-file')
    monkeypatch.setattr(app.state.mesh_services.nodes, 'observe', unavailable)
    response = client.get('/api/mesh/services/' + identity, headers=OWNER)
    assert response.status_code == 200 and not response.json()['observed']
    assert 'private-ssh-secret' not in response.text and '/root/' not in response.text
    with factory() as session:
        assert session.get(Job, ROUTE).payload == before
