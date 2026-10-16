"""Legacy benchmark endpoints must respect the same customer boundary."""
import hashlib
import threading

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Job, Node, NodeInventory
from orchestrator.benchmarking import Candidate, NodeCaps

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///'+str(tmp_path/'unused.db'))
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path/'customers'))
    monkeypatch.setenv('TP_LOCK_DIR', str(tmp_path/'leases'))
    monkeypatch.setenv('TP_RBAC_TOKENS', 'SUPER_ADMIN:'+hashlib.sha256(b'owner').hexdigest())
    release, started, cancelled = threading.Event(), threading.Event(), threading.Event()
    class Runner:
        def __init__(self, *args, **kwargs): pass
        def cancel(self): cancelled.set()
        def run(self):
            self.job.state = 'RUNNING'
            self.session.commit()
            started.set()
            release.wait(5)
            self.job.state = 'CANCELLED' if cancelled.is_set() else 'PASS'
            self.session.commit()
    def prepare(req):
        candidates = [Candidate('wireguard', 'default', 'WIREGUARD', 'VPN', 'COMPATIBLE')]
        return NodeCaps('a'), NodeCaps('b'), candidates, None
    monkeypatch.setattr('apps.api.benchmark_api.BenchmarkRunner', Runner)
    monkeypatch.setattr('orchestrator.pair_runtime.prepare_benchmark', lambda factory: prepare)
    from apps.api.main import create_app
    factory = sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'owner.db')))
    app = create_app(factory)
    client = TestClient(app)
    owner = {'Authorization': 'Bearer owner'}
    account = client.post('/api/workspaces', headers=owner, json={'name': 'Customer'}).json()
    customer = {'Authorization': 'Bearer '+account['api_key']}
    scope = app.state.workspace_registry.authenticate(account['api_key'])
    with scope['factory']() as session:
        for index, identity in enumerate(['a', 'b']):
            session.add(Node(id=identity, name=identity, host='8.8.8.'+str(index+1)))
            session.add(NodeInventory(node_id=identity, snapshot={'os': 'linux'}))
        session.commit()
    payload = {'node_a': {'node_id': 'a'}, 'node_b': {'node_id': 'b'}, 'methods': ['WIREGUARD']}
    try:
        yield client, factory, scope['factory'], owner, customer, payload, started, cancelled, release
    finally:
        release.set()
        client.close()


def test_known_other_customer_job_cannot_cancel_global_runner(panel):
    client, _, _, owner, customer, payload, started, cancelled, release = panel
    response = client.post('/benchmarks', headers=owner, json=payload)
    assert response.status_code == 200
    identity = response.json()['job_id']
    assert started.wait(2)
    assert client.post('/benchmarks/'+identity+'/cancel', headers=customer).status_code == 404
    assert not cancelled.is_set()
    assert client.post('/benchmarks/'+identity+'/cancel', headers=owner).status_code == 200
    assert cancelled.is_set()
    release.set()


def test_legacy_cancel_rejects_mesh_job_without_changing_its_state(panel):
    client, _, factory, _, customer, _, _, _, _ = panel
    with factory() as session:
        session.add(Job(id='mesh-parent', kind='mesh_campaign', state='QUEUED', payload={'routes': []}))
        session.commit()
    assert client.post('/benchmarks/mesh-parent/cancel', headers=customer).status_code == 404
    with factory() as session:
        assert session.get(Job, 'mesh-parent').state == 'QUEUED'


def test_legacy_and_mesh_admission_share_customer_active_budget(panel):
    client, _, _, _, customer, payload, started, _, release = panel
    first = client.post('/benchmarks', headers=customer, json=payload)
    assert first.status_code == 200
    assert started.wait(2)
    try:
        assert client.post('/benchmarks', headers=customer, json=payload).status_code == 409
        assert client.post('/api/mesh/campaigns', headers=customer,
            json={'nodes': ['a', 'b'], 'methods': ['WIREGUARD']}).status_code == 409
    finally:
        release.set()


def test_active_mesh_campaign_also_blocks_legacy_start(panel):
    client, _, factory, _, customer, payload, _, _, _ = panel
    with factory() as session:
        session.add(Job(id='active-mesh', kind='mesh_campaign', state='RUNNING', payload={'routes': []}))
        session.commit()
    assert client.post('/benchmarks', headers=customer, json=payload).status_code == 409


def test_legacy_respects_customer_method_budget(panel):
    client, _, _, owner, customer, payload, _, _, _ = panel
    accounts = client.get('/api/workspaces', headers=owner).json()
    assert client.patch('/api/workspaces/'+accounts[0]['id'], headers=owner,
        json={'limits': {'max_campaign_methods': 1}}).status_code == 200
    # The adapter returns one candidate; explicit oversized requests must be
    # rejected before any adapter can silently narrow the user's selection.
    payload = {**payload, 'methods': ['WIREGUARD', 'GRE']}
    assert client.post('/benchmarks', headers=customer, json=payload).status_code == 400


def test_campaign_child_uses_parent_cancellation_and_only_one_admission_slot(panel):
    client, _, factory, owner, customer, payload, _, _, release = panel
    account = client.get('/api/workspaces', headers=owner).json()[0]
    assert client.patch('/api/workspaces/'+account['id'], headers=owner,
        json={'limits': {'max_active_campaigns': 2}}).status_code == 200
    with factory() as session:
        session.add_all([
            Job(id='parent', kind='mesh_campaign', state='RUNNING', payload={'routes': []}),
            Job(id='child', kind='benchmark', state='RUNNING', payload={'campaign_id': 'parent'})])
        session.commit()
    assert client.post('/benchmarks/child/cancel', headers=customer).status_code == 409
    with factory() as session:
        assert session.get(Job, 'child').state == 'RUNNING'
    try:
        assert client.post('/benchmarks', headers=customer, json=payload).status_code == 200
        assert client.post('/benchmarks', headers=customer, json=payload).status_code == 409
    finally:
        release.set()


def test_legacy_queue_cannot_bypass_daily_budget_or_persist_untrusted_secrets(panel, monkeypatch):
    client, _, factory, owner, customer, payload, _, _, _ = panel
    monkeypatch.setattr('orchestrator.worker_slots.dispatch', lambda *args: False)
    account = client.get('/api/workspaces', headers=owner).json()[0]
    client.patch('/api/workspaces/'+account['id'], headers=owner,
                 json={'limits': {'max_daily_candidate_units': 1, 'max_active_campaigns': 2}})
    payload['node_a']['password'] = 'SECRET_CANARY_NOT_QUEUED'
    first = client.post('/benchmarks', headers=customer, json=payload)
    assert first.status_code == 200
    with factory() as session:
        job = session.get(Job, first.json()['job_id'])
        assert job.state == 'QUEUED' and job.payload['candidate_units'] == 1
        assert 'SECRET_CANARY' not in str(job.payload)
    assert client.post('/benchmarks/'+first.json()['job_id']+'/cancel', headers=customer).status_code == 200
    assert client.post('/benchmarks', headers=customer, json=payload).status_code == 429
    assert client.post('/benchmarks', headers=customer, json={**payload, 'max_parallel': 5000}).status_code == 422
