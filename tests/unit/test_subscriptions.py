"""Subscription state must be replay safe and never bypass tenant quotas."""
import hashlib
import hmac
import json
import secrets

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def billing(tmp_path):
    from core.workspaces import WorkspaceRegistry
    from core.subscriptions import SubscriptionStore
    registry = WorkspaceRegistry(tmp_path / 'customers')
    workspace = registry.create('Customer')
    now = [1800000000.0]
    secret = secrets.token_urlsafe(36)
    store = SubscriptionStore(registry, clock=lambda: now[0], webhook_secret=secret, mode='sandbox')
    return store, registry, workspace, now, secret


def event(billing, **changes):
    _, _, workspace, now, _ = billing
    return {'event_id': 'evt-initial', 'workspace_id': workspace['id'], 'revision': 1,
            'plan': 'starter', 'state': 'active', 'paid_through': now[0]+3600,
            'grace_until': now[0]+7200, 'mode': 'sandbox', **changes}


def send(billing, payload, *, raw=None, timestamp=None, signature=None):
    store, _, _, now, secret = billing
    raw = json.dumps(payload, separators=(',', ':')).encode() if raw is None else raw
    timestamp = str(int(now[0])) if timestamp is None else timestamp
    signature = signature or hmac.new(secret.encode(), timestamp.encode()+b'.'+raw, hashlib.sha256).hexdigest()
    return store.apply_event(raw, timestamp, signature)


def test_duplicate_and_out_of_order_events_cannot_double_grant_or_undo_renewal(billing):
    store, _, workspace, _, _ = billing
    first = event(billing)
    assert send(billing, first)['applied'] is True
    assert send(billing, first)['duplicate'] is True
    # JSON formatting is not a changed business event.
    assert send(billing, first, raw=json.dumps(first, sort_keys=True, indent=2).encode())['duplicate'] is True
    with pytest.raises(HTTPException) as error:
        send(billing, {**first, 'plan': 'team'})
    assert error.value.status_code == 409
    renewal = event(billing, event_id='evt-renewal', revision=3, plan='pro')
    assert send(billing, renewal)['applied'] is True
    stale = event(billing, event_id='evt-late-cancel', revision=2, state='cancelled')
    assert send(billing, stale)['applied'] is False
    assert store.status(workspace['id'])['plan'] == 'pro'
    assert store.status(workspace['id'])['state'] == 'active'


def test_expiry_cleanup_rechecks_revision_and_cannot_repeat_after_restart(billing):
    store, _, workspace, now, _ = billing
    send(billing, event(billing))
    store.set_policy(workspace['id'], stop_on_expiry=True)
    now[0] += 7201
    pending = store.expiry_candidates()[0]
    calls = []
    send(billing, event(billing, event_id='renewed', revision=2))
    assert not store.run_expiry_action(workspace['id'], pending['revision'], lambda: calls.append('stale'))
    assert calls == []
    now[0] += 7201
    assert store.run_expiry_action(workspace['id'], 2, lambda: calls.append('stopped') or True)
    assert not store.run_expiry_action(workspace['id'], 2, lambda: calls.append('duplicate') or True)
    assert calls == ['stopped']


def test_sandbox_cancellation_is_idempotent_and_can_be_renewed(billing):
    store,_,workspace,_,_=billing
    store.sandbox_grant(workspace['id'],'pro')
    first=store.sandbox_cancel(workspace['id'])
    assert first['state']=='cancelled' and first['can_start_work'] is False
    assert store.sandbox_cancel(workspace['id'])['revision']==first['revision']
    assert store.sandbox_grant(workspace['id'],'starter')['state']=='active'


def test_only_matching_active_grant_fulfills_a_plan_request(billing):
    store,_,workspace,_,_=billing
    store.request_plan(workspace['id'],'pro')
    store.sandbox_grant(workspace['id'],'starter')
    assert store.requests(workspace['id'])[0]['state']=='PENDING_OWNER_ACTIVATION'
    store.sandbox_cancel(workspace['id'])
    assert store.requests(workspace['id'])[0]['state']=='PENDING_OWNER_ACTIVATION'
    store.sandbox_grant(workspace['id'],'pro')
    assert store.requests(workspace['id'])[0]['state']=='APPROVED_SANDBOX'


def test_bad_signature_skew_mode_and_payload_are_rejected_without_state_change(billing):
    store, _, workspace, now, _ = billing
    for arguments in [
        {'signature': '0'*64}, {'timestamp': str(int(now[0]-301))},
        {'raw': b'not-json'}, {'raw': b'x'*16385},
    ]:
        with pytest.raises(HTTPException):
            send(billing, event(billing), **arguments)
    with pytest.raises(HTTPException):
        send(billing, event(billing, mode='bridge'))
    with pytest.raises(HTTPException):
        send(billing, event(billing, paid_through=float('nan')))
    with pytest.raises(HTTPException):
        send(billing, event(billing, workspace_id='system'))
    assert store.status(workspace['id'])['state'] == 'legacy'


def test_grace_expiry_preserves_read_stop_and_legacy_behavior(billing):
    store, _, workspace, now, _ = billing
    assert store.authorize_operation(workspace['id'], 'POST', '/api/mesh/campaigns') is None
    send(billing, event(billing))
    assert store.status(workspace['id'])['mode'] == 'sandbox'
    assert store.status(workspace['id'])['payment_collected'] is False
    assert store.status(workspace['id'])['limits']['max_nodes'] == 2
    now[0] += 3601
    assert store.status(workspace['id'])['state'] == 'past_due'
    assert store.authorize_operation(workspace['id'], 'POST', '/api/mesh/routes') is None
    now[0] += 3600
    assert store.status(workspace['id'])['state'] == 'expired'
    with pytest.raises(HTTPException) as error:
        store.authorize_operation(workspace['id'], 'POST', '/api/mesh/routes')
    assert error.value.status_code == 402
    for method, path in [('GET', '/api/nodes'), ('GET', '/api/operations/support'),
                         ('DELETE', '/api/mesh/routes/owned'), ('POST', '/benchmarks/owned/cancel'),
                         ('PUT', '/api/nodes/owned'), ('POST', '/api/billing/requests'),
                         ('POST', '/auth/logout')]:
        assert store.authorize_operation(workspace['id'], method, path) is None


def test_expiry_cleanup_is_explicit_scoped_and_invalidated_by_renewal(billing):
    store, registry, workspace, now, _ = billing
    other = registry.create('Other')
    send(billing, event(billing, paid_through=now[0]-10, grace_until=now[0]-1))
    assert store.expiry_candidates() == []
    store.set_policy(workspace['id'], stop_on_expiry=True)
    assert store.expiry_candidates() == [{'workspace_id': workspace['id'], 'revision': 1}]
    assert all(x['workspace_id'] != other['id'] for x in store.expiry_candidates())
    send(billing, event(billing, event_id='renewed', revision=2))
    assert store.expiry_candidates() == []


def test_concurrent_duplicate_events_apply_once_and_snapshot_retains_state(billing, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from core.workspace_backup import snapshot_workspaces, validate_snapshot
    from core.subscriptions import SubscriptionStore
    from core.workspaces import WorkspaceRegistry
    store, registry, workspace, _, secret = billing
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: send(billing, event(billing)), range(2)))
    assert sum(not x['duplicate'] for x in responses) == 1
    target = tmp_path / 'snapshot'
    assert snapshot_workspaces(registry.directory, target)['workspaces'] == 1
    validate_snapshot(target)
    restored = SubscriptionStore(WorkspaceRegistry(target), clock=store.clock, webhook_secret=secret, mode='sandbox')
    assert restored.status(workspace['id'])['plan'] == 'starter'
    assert send((restored, registry, workspace, [store.clock()], secret), event(billing))['duplicate'] is True


def test_http_billing_is_owner_scoped_and_expired_customer_can_still_read(tmp_path, monkeypatch):
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path / 'customers'))
    monkeypatch.setenv('TP_SECRET_KEY', secrets.token_urlsafe(32))
    monkeypatch.setenv('TP_RBAC_TOKENS', 'SUPER_ADMIN:' + hashlib.sha256(b'owner').hexdigest())
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(tmp_path / 'unused.db'))
    secret = secrets.token_urlsafe(36)
    monkeypatch.setenv('TP_BILLING_WEBHOOK_SECRET', secret)
    from apps.api.main import create_app
    app = create_app(sessionmaker(bind=create_engine('sqlite:///' + str(tmp_path / 'owner.db'))))
    client = TestClient(app)
    owner = {'Authorization': 'Bearer owner'}
    a = client.post('/api/workspaces', headers=owner, json={'name': 'A'}).json()
    b = client.post('/api/workspaces', headers=owner, json={'name': 'B'}).json()
    ah, bh = {'Authorization': 'Bearer '+a['api_key']}, {'Authorization': 'Bearer '+b['api_key']}
    assert client.get('/api/billing/status', headers=ah).json()['state'] == 'legacy'
    assert client.get('/api/billing/workspaces', headers=ah).status_code == 403
    assert client.post('/api/billing/workspaces/'+b['id']+'/policy', headers=ah,
                       json={'stop_on_expiry': True}).status_code == 403
    now = app.state.subscriptions.clock()
    bundle = (app.state.subscriptions, app.state.workspace_registry, a, [now], secret)
    payload = event(bundle, paid_through=now-10, grace_until=now-1)
    raw, timestamp = json.dumps(payload).encode(), str(int(now))
    signature = hmac.new(secret.encode(), timestamp.encode()+b'.'+raw, hashlib.sha256).hexdigest()
    response = client.post('/billing/events', content=raw, headers={
        'Content-Type': 'application/json', 'X-TP-Timestamp': timestamp, 'X-TP-Signature': signature})
    assert response.status_code == 200
    assert client.get('/api/billing/status', headers=ah).json()['state'] == 'expired'
    assert client.get('/api/nodes', headers=ah).status_code == 200
    assert client.post('/api/mesh/campaigns', headers=ah, json={'nodes': ['a','b']}).status_code == 402
    assert client.post('/api/mesh/campaigns', headers=bh, json={'nodes': ['a','b']}).status_code == 400
    request = client.post('/api/billing/requests', headers=ah, json={'plan':'pro'})
    assert request.status_code == 201
    assert request.json()['payment_collected'] is False
    assert len(client.get('/api/billing/requests', headers=ah).json()) == 1
    assert client.get('/api/billing/requests', headers=bh).json() == []
    assert len(client.get('/api/billing/owner/requests', headers=owner).json()) == 1
    assert client.get('/api/billing/workspaces', headers=owner).status_code == 200
    grant = client.post('/api/billing/workspaces/'+a['id']+'/sandbox-grant', headers=owner,
                        json={'plan': 'starter', 'days': 1, 'grace_hours': 0})
    assert grant.status_code == 200
    assert grant.json()['state'] == 'active' and grant.json()['payment_collected'] is False
    assert client.get('/api/mesh/config', headers=ah).json()['limits']['max_nodes'] == 2
    for index in range(3):
        node = {'name': 'node'+str(index), 'host': '8.8.8.'+str(index+8),
                'host_key_fingerprint': 'a'*64, 'password': 'node-test-password'}
        response = client.post('/api/nodes', headers=ah, json=node)
        assert response.status_code == (201 if index < 2 else 409)
    assert client.get('/api/nodes', headers=bh).json() == []
    assert client.get('/billing/plans').json()['checkout_available'] is False


def test_disabled_workspace_stays_disabled_after_signed_renewal(billing):
    store, registry, workspace, _, _ = billing
    send(billing, event(billing))
    registry.disable(workspace['id'])
    assert send(billing, event(billing, event_id='renew-disabled', revision=2))['applied'] is True
    assert registry.authenticate(workspace['api_key']) is None
    assert store.status(workspace['id'])['revision'] == 2
