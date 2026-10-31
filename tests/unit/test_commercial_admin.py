"""Paid manual access, username lifecycle and owner-only administration."""
import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def commerce(tmp_path):
    from core.accounts import AccountStore
    from core.subscriptions import SubscriptionStore
    from core.workspaces import WorkspaceRegistry
    registry = WorkspaceRegistry(tmp_path / 'customers')
    workspace = registry.create('Customer')
    now = [1800000000.0]
    accounts = AccountStore(registry, clock=lambda: now[0])
    subscriptions = SubscriptionStore(registry, clock=lambda: now[0], mode='manual')
    return registry, workspace, accounts, subscriptions, now


def create(commerce, **changes):
    _, workspace, accounts, _, _ = commerce
    return accounts.create_managed(workspace['id'], username='customer-one',
                                   password='local-customer-password', **changes)


def plan(commerce, **changes):
    _, _, _, store, _ = commerce
    return store.save_plan('business', {'name': 'Business', 'price_minor': 250000,
        'currency': 'IRT', 'duration_days': 30, 'enabled': True,
        'limits': {'max_nodes': 3, 'max_daily_candidate_units': 25}, **changes})


def payment(commerce, **changes):
    _, workspace, _, store, _ = commerce
    return store.record_manual_payment(workspace['id'], {'request_id': 'receipt-unique-001',
        'plan': 'business', 'amount_minor': 250000, 'currency': 'IRT',
        'reference': 'bank-confirmation-001', **changes}, actor='owner-account')


def test_username_login_preserves_email_compatibility_and_hashes_password(commerce):
    registry, workspace, accounts, _, _ = commerce
    account = create(commerce, email='customer@example.test')
    assert account['username'] == 'customer-one' and account['enabled']
    for login in ['CUSTOMER-ONE', 'customer@example.test']:
        assert accounts.login(login, 'local-customer-password')['account']['id'] == account['id']
    with registry._connect() as db:
        row = db.execute('SELECT password_hash FROM accounts').fetchone()
        assert row['password_hash'].startswith('scrypt$')
        assert 'local-customer-password' not in row['password_hash']
    assert accounts.list_accounts()[0]['workspace_id'] == workspace['id']


def test_user_edits_revoke_sessions_without_resetting_customer_identity(commerce):
    _, workspace, accounts, _, _ = commerce
    account = create(commerce)
    token = accounts.login('customer-one', 'local-customer-password')['token']
    result = accounts.update_managed(account['id'], {'username': 'renamed-user',
        'display_name': 'Customer renamed', 'role': 'VIEWER', 'enabled': False})
    assert result['id'] == account['id'] and result['workspace_id'] == workspace['id']
    assert accounts.authenticate_session(token) is None
    with pytest.raises(HTTPException):
        accounts.login('renamed-user', 'local-customer-password')
    accounts.update_managed(account['id'], {'enabled': True, 'password': 'changed-customer-password'})
    assert accounts.login('renamed-user', 'changed-customer-password')['account']['role'] == 'VIEWER'


@pytest.mark.parametrize('change', [{'enabled': False}, {'role': 'VIEWER'}])
def test_last_system_owner_cannot_be_disabled_or_demoted(commerce, change):
    accounts = commerce[2]
    account = accounts.create_managed('system', username='system-owner', password='local-owner-password')
    with pytest.raises(HTTPException) as error:
        accounts.update_managed(account['id'], change)
    assert error.value.status_code == 409
    assert accounts.login('system-owner', 'local-owner-password')['account']['enabled']


def test_username_collision_and_reserved_email_syntax_are_rejected(commerce):
    accounts = commerce[2]
    create(commerce)
    with pytest.raises(HTTPException) as error:
        accounts.create_managed('system', username='CUSTOMER-ONE', password='another-owner-password')
    assert error.value.status_code == 409
    with pytest.raises(HTTPException):
        accounts.create_managed('system', username='not@a-username', password='another-owner-password')


def test_manual_mode_never_grants_free_new_work_and_preserves_owner(commerce):
    _, workspace, _, store, _ = commerce
    assert store.status(workspace['id'])['can_start_work'] is False
    assert store.status('system')['can_start_work'] is True
    with pytest.raises(HTTPException) as error:
        store.authorize_operation(workspace['id'], 'POST', '/api/mesh/campaigns')
    assert error.value.status_code == 402
    store.authorize_operation(workspace['id'], 'GET', '/api/nodes')
    store.authorize_operation(workspace['id'], 'DELETE', '/api/mesh/routes/owned')


def test_payment_activates_once_and_plan_edits_do_not_rewrite_existing_entitlements(commerce):
    _, workspace, _, store, now = commerce
    plan(commerce)
    first = payment(commerce)
    original = store.status(workspace['id'])
    assert first['duplicate'] is False and original['mode'] == 'manual'
    assert original['limits']['max_nodes'] == 3 and original['can_start_work']
    assert payment(commerce)['duplicate'] is True
    assert store.status(workspace['id'])['paid_through'] == original['paid_through']
    plan(commerce, limits={'max_nodes': 2, 'max_daily_candidate_units': 10})
    assert store.status(workspace['id'])['limits']['max_nodes'] == 3
    now[0] = original['paid_through'] + 1
    assert not store.status(workspace['id'])['can_start_work']
    assert len(store.manual_payments()) == 1


def test_receipt_replay_with_different_content_or_reference_cannot_extend_access(commerce):
    plan(commerce);payment(commerce)
    before = commerce[3].status(commerce[1]['id'])
    for changes in [{'amount_minor': 250001}, {'request_id': 'another-id'}]:
        with pytest.raises(HTTPException) as error:
            payment(commerce, **changes)
        assert error.value.status_code == 409
    assert commerce[3].status(commerce[1]['id']) == before


def test_parallel_same_receipt_only_activates_one_period(commerce):
    plan(commerce)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: payment(commerce), range(2)))
    assert sorted(r['duplicate'] for r in results) == [False, True]
    assert commerce[3].status(commerce[1]['id'])['paid_through'] == commerce[4][0] + 30*86400


def test_renewal_extends_remaining_time_and_workspace_caps_still_apply(commerce):
    registry, workspace, _, store, now = commerce
    plan(commerce);payment(commerce)
    registry.update(workspace['id'], limits={'max_nodes': 1})
    payment(commerce, request_id='receipt-unique-002', reference='bank-confirmation-002')
    status = store.status(workspace['id'])
    assert status['paid_through'] == now[0] + 60*86400
    assert status['limits']['max_nodes'] == 1


@pytest.mark.parametrize('changes', [{'amount_minor': 0}, {'amount_minor': True}, {'currency': 'USD'}])
def test_invalid_manual_payments_never_activate_access(commerce, changes):
    plan(commerce)
    with pytest.raises(HTTPException):
        payment(commerce, **changes)
    assert not commerce[3].status(commerce[1]['id'])['can_start_work']
    assert commerce[3].manual_payments() == []


def test_owner_api_customer_boundary_csrf_and_admin_assets(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///'+str(tmp_path/'unused.db'))
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path/'workspaces'))
    monkeypatch.setenv('TP_BILLING_MODE', 'manual')
    monkeypatch.setenv('TP_RBAC_TOKENS', 'SUPER_ADMIN:'+hashlib.sha256(b'owner').hexdigest())
    from apps.api.main import create_app
    app = create_app(sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'owner.db'))))
    client = TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 35000))
    owner = {'Authorization': 'Bearer owner'}
    workspace = client.post('/api/workspaces', headers=owner, json={'name': 'Paid customer'}).json()
    created = client.post('/api/accounts', headers=owner, json={'workspace_id': workspace['id'],
        'username': 'paid-customer', 'password': 'local-customer-password'})
    assert created.status_code == 201
    assert 'password' not in created.text
    login = client.post('/auth/login', json={'username': 'paid-customer', 'password': 'local-customer-password'})
    assert login.status_code == 200
    csrf = {'X-CSRF-Token': login.json()['csrf']}
    assert client.get('/api/accounts').status_code == 403
    assert client.get('/api/billing/owner/payments').status_code == 403
    assert client.put('/api/billing/owner/plans/starter', headers=csrf, json={}).status_code == 403
    assert client.post('/api/mesh/campaigns', headers=csrf, json={}).status_code == 402
    assert client.get('/api/nodes').status_code == 200
    assert client.get('/assets/admin.js').status_code == 200
    assert client.get('/portal').headers['content-security-policy']
    owner_body = {'workspace_id':'system','username':'system-owner','password':'local-owner-password'}
    assert client.post('/api/accounts',headers=owner,json=owner_body).status_code == 201
    owner_login = client.post('/auth/login',json={'username':'system-owner','password':'local-owner-password'})
    assert owner_login.status_code == 200
    owner_csrf = {'X-CSRF-Token':owner_login.json()['csrf']}
    plan_body = {'name':'Paid starter','price_minor':200000,'currency':'IRT','duration_days':10,
                 'enabled':True,'limits':{'max_nodes':2,'max_daily_candidate_units':5}}
    assert client.put('/api/billing/owner/plans/paid',json=plan_body).status_code == 403
    assert client.put('/api/billing/owner/plans/paid',headers=owner_csrf,json=plan_body).status_code == 200
    receipt = {'request_id':'public-api-001','plan':'paid','amount_minor':200000,'currency':'IRT','reference':'bank-ref-api-001'}
    url='/api/billing/owner/workspaces/'+workspace['id']+'/payments'
    assert client.post(url,headers=owner_csrf,json=receipt).status_code == 200
    assert client.post(url,headers=owner_csrf,json=receipt).json()['duplicate'] is True
    assert client.get('/api/billing/owner/payments').json()[0]['amount_minor'] == 200000


def test_plan_limits_reject_boolean_instead_of_silently_granting_one(commerce):
    with pytest.raises(HTTPException):
        plan(commerce,limits={'max_nodes':True})


def test_portal_script_bindings_exist_in_the_served_template():
    import re
    from pathlib import Path
    root=Path(__file__).resolve().parents[2]/'apps/web'
    html=(root/'portal.html').read_text(encoding='utf8')
    ids=set(re.findall(r'id="([^"]+)"',html))
    refs=set(re.findall(r"\$\('([^']+)'\)",(root/'portal.js').read_text(encoding='utf8')))
    assert refs <= ids, refs-ids


def test_switch_to_manual_does_not_turn_old_sandbox_credit_into_paid_access(commerce):
    from core.subscriptions import SubscriptionStore
    registry,workspace,_,store,now=commerce
    sandbox=SubscriptionStore(registry,mode='sandbox',clock=lambda:now[0])
    sandbox.sandbox_grant(workspace['id'],'starter',days=30)
    assert not store.status(workspace['id'])['can_start_work']
    plan(commerce);payment(commerce)
    assert store.status(workspace['id'])['paid_through']==now[0]+30*86400


def test_receipt_and_entitlement_are_one_atomic_transaction(commerce):
    registry,workspace,_,store,_=commerce
    plan(commerce)
    with registry._connect() as db:
        db.execute("CREATE TRIGGER reject_qa_subscription BEFORE INSERT ON billing_subscriptions "
                   "BEGIN SELECT RAISE(ABORT,'qa-subscription-write-failed'); END")
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):payment(commerce)
    assert store.manual_payments()==[]
    assert not store.status(workspace['id'])['can_start_work']
