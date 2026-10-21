import pytest
from test_mesh_api import HEADERS, panel  # noqa: F401

pytestmark = pytest.mark.unit_portable


def test_route_creation_requires_a_customer_visible_completed_campaign(panel):
    client, _, _ = panel
    response = client.post('/api/mesh/routes', headers=HEADERS,
                           json={'campaign_id': 'missing', 'route_id': 'missing'})
    assert response.status_code == 404
    assert 'campaign not found' in response.text


def test_traffic_edit_rejects_historical_workers_and_cross_customer_access(panel, monkeypatch):
    from core.models import Job
    client, factory, _ = panel
    with factory() as session:
        session.add(Job(id='historical', kind='mesh_route', state='COMMITTED',
                        payload={'source': 'ir', 'destination': 'de', 'methods': ['GRE']}))
        session.commit()
    monkeypatch.setattr('orchestrator.mesh_routes.observe_route',
                        lambda *args: {'observed': True, 'runtime': {'worker_pid': 42}})
    response = client.put('/api/mesh/routes/historical/traffic', headers=HEADERS, json={})
    assert response.status_code == 409
    assert 'cannot enforce' in response.text
    monkeypatch.setattr('orchestrator.mesh_routes.observe_route',
                        lambda *args: (_ for _ in ()).throw(__import__('fastapi').HTTPException(404, 'route not found')))
    assert client.put('/api/mesh/routes/foreign/traffic', headers=HEADERS, json={}).status_code == 404
    assert client.put('/api/mesh/routes/foreign/traffic', headers=HEADERS, json={'quota_bytes': True}).status_code == 422


def test_customer_cannot_read_or_stop_an_owner_route(panel):
    from core.models import Job
    client, factory, _ = panel
    with factory() as session:
        session.add(Job(id='owner-route', kind='mesh_route', state='COMMITTED',
                        payload={'source': 'ir', 'destination': 'de', 'methods': ['WIREGUARD']}))
        session.commit()
    account = client.post('/api/workspaces', headers=HEADERS, json={'name': 'Customer'}).json()
    headers = {'Authorization': 'Bearer ' + account['api_key']}
    assert client.get('/api/mesh/routes', headers=headers).json() == []
    assert client.get('/api/mesh/routes/owner-route', headers=headers).status_code == 404
    assert client.delete('/api/mesh/routes/owner-route', headers=headers).status_code == 404


def test_customer_viewer_cannot_retrieve_private_outbound_credentials(panel, monkeypatch):
    import hashlib
    client, _, _ = panel
    monkeypatch.setenv('TP_RBAC_TOKENS', 'VIEWER:' + hashlib.sha256(b'viewer-route-key').hexdigest())
    response = client.get('/api/mesh/routes/owner-route/outbound',
                           headers={'Authorization': 'Bearer viewer-route-key'})
    assert response.status_code == 403


def test_old_worker_health_is_not_current_readiness_after_a_restart(panel, monkeypatch):
    import json
    import time
    from core.models import Job, SecretReference
    from orchestrator.remote_nodes import encrypt_credentials
    from orchestrator.mesh_routes import observe_route
    monkeypatch.setenv('TP_SECRET_KEY', 'route-test-installation-secret')
    _, factory, _ = panel
    with factory() as session:
        secret = SecretReference(kind='mesh_runtime', ciphertext=encrypt_credentials(
            {'directory': '/owned/gateway', 'service': 'owned-unit',
             'config': {'listen_host': '127.0.0.1', 'listen_port': 24000}}))
        session.add(secret)
        session.flush()
        session.add(Job(id='test-route', kind='mesh_route', state='COMMITTED', payload={
            'source': 'ir', 'destination': 'de', 'runtime_secret_id': secret.id}))
        session.commit()
    monkeypatch.setattr('orchestrator.mesh_routes.node_access', lambda *args: ({}, {}))
    class Remote:
        def __init__(self, *args): pass
        def connect(self): return self
        def close(self): pass
        def run(self, command, **kwargs):
            if command.startswith('cat '):
                return {'code': 0, 'stdout': json.dumps({'worker_pid': 41, 'updated_at': time.time(), 'active': 'GRE'})}
            return {'code': 0, 'stdout': '42\n'}
    monkeypatch.setattr('orchestrator.mesh_routes.NodeRemote', Remote)
    result = observe_route(factory, 'test-route')
    assert result['observed'] is False


def test_reconcile_can_change_order_and_count_using_only_this_routes_measured_results(panel, monkeypatch):
    from core.models import Job
    from test_mesh_campaign import sample
    client, factory, app = panel
    monkeypatch.setattr('orchestrator.mesh_routes.route_samples', lambda *args: [sample('GRE'), sample('IPIP')])
    monkeypatch.setattr(app.state.mesh_routes, 'kick', lambda *args: None)
    with factory() as session:
        session.add(Job(id='proof-campaign', kind='mesh_campaign', state='PASS', payload={
            'routes': [{'id': 'pair', 'source': 'ir', 'destination': 'de', 'job_id': 'proof-child'}]}))
        session.add(Job(id='warm-route', kind='mesh_route', state='COMMITTED', payload={
            'source': 'ir', 'destination': 'de', 'campaign_id': 'proof-campaign', 'campaign_route_id': 'pair',
            'runtime_secret_id': 'keep-stable-endpoint', 'methods': ['GRE']}))
        session.commit()
    path = '/api/mesh/routes/warm-route/reconcile'
    assert client.post(path, headers=HEADERS, json={'methods': ['WIREGUARD']}).status_code == 400
    assert client.post(path, headers=HEADERS, json={'methods': ['IPIP', 'GRE']}).status_code == 202
    with factory() as session:
        job = session.get(Job, 'warm-route')
        assert job.state == 'APPLYING'
        assert job.payload['methods'] == ['IPIP', 'GRE']
        assert job.payload['runtime_secret_id'] == 'keep-stable-endpoint'


def test_route_accepts_balance_mode_and_rejects_unknown_modes(panel, monkeypatch):
    from core.models import Job
    from test_mesh_campaign import sample
    client, factory, app = panel
    monkeypatch.setattr('orchestrator.mesh_routes.route_samples', lambda *args: [sample('GRE')])
    monkeypatch.setattr(app.state.mesh_routes, 'kick', lambda *args: None)
    with factory() as session:
        session.add(Job(id='measured', kind='mesh_campaign', state='PASS', payload={
            'routes': [{'id': 'pair', 'source': 'ir', 'destination': 'de', 'job_id': 'child'}]}))
        session.commit()
    body = {'campaign_id': 'measured', 'route_id': 'pair', 'methods': ['GRE'], 'mode': 'balance'}
    response = client.post('/api/mesh/routes', headers=HEADERS, json=body)
    assert response.status_code == 202
    with factory() as session:
        assert session.get(Job, response.json()['id']).payload['mode'] == 'balance'
    assert client.post('/api/mesh/routes', headers=HEADERS,
        json={**body, 'mode': 'unimplemented-stream-bonding'}).status_code == 422


def test_live_mode_change_preserves_entry_credentials_members_and_omitted_pin(panel, monkeypatch):
    import json
    from core.models import Job, SecretReference
    from orchestrator.remote_nodes import encrypt_credentials
    from orchestrator.mesh_routes import route_private
    monkeypatch.setenv('TP_SECRET_KEY', 'route-test-installation-secret')
    client, factory, _ = panel
    config = {'mode': 'failover', 'pin': 'GRE', 'listen_host': '127.0.0.1', 'listen_port': 24000,
        'username': 'unit-user', 'password': 'unit-only-not-deployed-password',
        'upstreams': [{'id': 'GRE', 'weight': 100}, {'id': 'IPIP', 'weight': 50}]}
    with factory() as session:
        secret = SecretReference(kind='mesh_runtime', ciphertext=encrypt_credentials(
            {'directory': '/owned/gateway', 'service': 'owned-unit', 'config': config}))
        session.add(secret); session.flush()
        session.add(Job(id='mode-route', kind='mesh_route', state='COMMITTED', payload={
            'source': 'ir', 'destination': 'de', 'runtime_secret_id': secret.id}))
        session.commit()
    monkeypatch.setattr('orchestrator.mesh_routes.node_access', lambda *args: ({}, {}))
    class Remote:
        def __init__(self, *args): pass
        def connect(self): return self
        def close(self): pass
        def run(self, *args, **kwargs): return {'code': 0, 'stdout': ''}
    written = {}
    monkeypatch.setattr('orchestrator.mesh_routes.NodeRemote', Remote)
    monkeypatch.setattr('plan_executor.executor.write_remote_text',
        lambda remote,path,content,mode: written.update(json.loads(content)))
    url = '/api/mesh/routes/mode-route/policy'
    assert client.put(url, headers=HEADERS, json={'mode': 'balance'}).status_code == 200
    assert written == {**config, 'mode': 'balance'}
    with factory() as session:
        job = session.get(Job, 'mode-route')
        assert job.payload['mode'] == 'balance'
        assert route_private(session, job)['config'] == written
    assert client.put(url, headers=HEADERS, json={'mode': 'invalid'}).status_code == 422
