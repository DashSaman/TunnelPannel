"""Invites, sessions and OTPs must preserve the existing tenant boundary."""
import base64
import hashlib

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def identity(tmp_path, monkeypatch):
    monkeypatch.setenv('TP_SECRET_KEY', 'installation-test-key-for-accounts')
    from core.workspaces import WorkspaceRegistry
    from core.accounts import AccountStore
    registry = WorkspaceRegistry(tmp_path / 'customers')
    account = registry.create('Customer')
    now = [1800000000.0]
    store = AccountStore(registry, clock=lambda: now[0])
    return store, registry, account, now


def register(identity, email='alice@example.test', role='SUPER_ADMIN'):
    store, _, workspace, _ = identity
    invitation = store.invite(workspace['id'], email, role=role, ttl_s=600)
    return store.register(invitation['token'], email, 'a-long-test-password')


def test_invitation_is_single_use_bound_to_email_and_stores_no_password(identity):
    store, registry, workspace, _ = identity
    invitation = store.invite(workspace['id'], 'alice@example.test', ttl_s=600)
    with pytest.raises(HTTPException):
        store.register(invitation['token'], 'other@example.test', 'a-long-test-password')
    account = store.register(invitation['token'], 'ALICE@example.test', 'a-long-test-password')
    assert account['workspace_id'] == workspace['id']
    with pytest.raises(HTTPException):
        store.register(invitation['token'], 'alice@example.test', 'a-long-test-password')
    with registry._connect() as db:
        row = db.execute('SELECT password_hash FROM accounts').fetchone()
        assert row['password_hash'].startswith('scrypt$')
        assert 'a-long-test-password' not in row['password_hash']
        assert invitation['token'] not in repr(db.execute('SELECT * FROM account_invites').fetchall())


def test_expired_invitation_and_short_password_do_not_create_account(identity):
    store, _, workspace, now = identity
    invitation = store.invite(workspace['id'], 'alice@example.test', ttl_s=60)
    with pytest.raises(HTTPException):
        store.register(invitation['token'], 'alice@example.test', 'short')
    now[0] += 61
    with pytest.raises(HTTPException):
        store.register(invitation['token'], 'alice@example.test', 'a-long-test-password')


def test_session_logout_idle_and_absolute_expiry(identity):
    store, _, workspace, now = identity
    register(identity)
    session = store.login('alice@example.test', 'a-long-test-password', peer='127.0.0.1')
    assert store.authenticate_session(session['token'])['workspace_id'] == workspace['id']
    store.logout(session['token'])
    assert store.authenticate_session(session['token']) is None
    session = store.login('alice@example.test', 'a-long-test-password', peer='127.0.0.1')
    now[0] += 1801
    assert store.authenticate_session(session['token']) is None
    session = store.login('alice@example.test', 'a-long-test-password', peer='127.0.0.1')
    for _ in range(48):
        now[0] += 899
        assert store.authenticate_session(session['token']) is not None
    now[0] += 49
    assert store.authenticate_session(session['token']) is None


def test_wrong_password_is_throttled_and_workspace_disable_revokes_session(identity):
    store, registry, workspace, _ = identity
    register(identity)
    valid = store.login('alice@example.test', 'a-long-test-password', peer='127.0.0.2')
    for _ in range(10):
        with pytest.raises(HTTPException) as error:
            store.login('alice@example.test', 'wrong', peer='127.0.0.3')
        assert error.value.status_code == 401
    with pytest.raises(HTTPException) as error:
        store.login('alice@example.test', 'a-long-test-password', peer='127.0.0.3')
    assert error.value.status_code == 429
    registry.disable(workspace['id'])
    assert store.authenticate_session(valid['token']) is None


def test_totp_rfc_vector_replay_and_single_use_recovery(identity):
    from core.accounts import totp_code
    seed = base64.b32encode(b'12345678901234567890').decode()
    assert totp_code(seed, 59) == '287082'
    assert totp_code(seed, 1111111109) == '081804'
    store, _, _, now = identity
    account = register(identity)
    setup = store.begin_totp(account['id'], 'a-long-test-password')
    code = totp_code(setup['secret'], now[0])
    recovery = store.enable_totp(account['id'], code)
    with pytest.raises(HTTPException):
        store.login('alice@example.test', 'a-long-test-password', otp=code, peer='127.0.0.1')
    now[0] += 30
    fresh = totp_code(setup['secret'], now[0])
    assert store.login('alice@example.test', 'a-long-test-password', otp=fresh, peer='127.0.0.1')['account']['mfa_enabled']
    with pytest.raises(HTTPException):
        store.login('alice@example.test', 'a-long-test-password', otp=fresh, peer='127.0.0.1')
    assert store.login('alice@example.test', 'a-long-test-password', otp=recovery['recovery_codes'][0], peer='127.0.0.1')
    with pytest.raises(HTTPException):
        store.login('alice@example.test', 'a-long-test-password', otp=recovery['recovery_codes'][0], peer='127.0.0.1')


def test_cookie_login_scope_csrf_role_and_owner_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path / 'customers'))
    monkeypatch.setenv('TP_SECRET_KEY', 'installation-test-key-for-accounts')
    monkeypatch.setenv('TP_RBAC_TOKENS', 'SUPER_ADMIN:' + hashlib.sha256(b'owner').hexdigest())
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(tmp_path / 'unused.db'))
    from apps.api.main import create_app
    app = create_app(sessionmaker(bind=create_engine('sqlite:///' + str(tmp_path / 'owner.db'))))
    owner = {'Authorization': 'Bearer owner'}
    client = TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 12345))
    workspace = client.post('/api/workspaces', headers=owner, json={'name': 'Customer'}).json()
    invite = client.post('/api/accounts/invitations', headers=owner,
        json={'workspace_id': workspace['id'], 'email': 'viewer@example.test', 'role': 'VIEWER'} )
    assert invite.status_code == 201
    origin = {'Origin': 'http://127.0.0.1'}
    response = client.post('/auth/register', headers=origin, json={
        'invitation': invite.json()['token'], 'email': 'viewer@example.test', 'password': 'a-long-test-password'})
    assert response.status_code == 201
    login = client.post('/auth/login', headers=origin,
        json={'email': 'viewer@example.test', 'password': 'a-long-test-password'})
    assert login.status_code == 200
    assert 'httponly' in login.headers['set-cookie'].lower()
    assert 'samesite=strict' in login.headers['set-cookie'].lower()
    assert 'token' not in login.json()
    csrf = login.json()['csrf']
    assert client.get('/api/whoami').json()['workspace_id'] == workspace['id']
    assert client.get('/api/workspaces').status_code == 403
    assert client.get('/api/accounts').status_code == 403
    assert client.post('/api/nodes', json={}).status_code == 403
    assert client.post('/api/nodes', headers={**origin, 'X-CSRF-Token': csrf}, json={}).status_code == 403
    assert client.post('/auth/logout', headers={**origin, 'X-CSRF-Token': csrf}).status_code == 200
    assert client.get('/api/whoami').status_code == 401


def test_public_origin_uses_secure_cookie_and_rejects_cross_origin_login(tmp_path, monkeypatch):
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path / 'customers'))
    monkeypatch.setenv('TP_PUBLIC_ORIGIN', 'https://panel.example.test')
    monkeypatch.setenv('TP_SECRET_KEY', 'installation-test-key-for-accounts')
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(tmp_path / 'unused.db'))
    from apps.api.main import create_app
    app = create_app(sessionmaker(bind=create_engine('sqlite:///' + str(tmp_path / 'owner.db'))))
    store = app.state.accounts
    workspace = app.state.workspace_registry.create('Customer')
    invitation = store.invite(workspace['id'], 'alice@example.test')
    store.register(invitation['token'], 'alice@example.test', 'a-long-test-password')
    client = TestClient(app, base_url='https://panel.example.test')
    body = {'email': 'alice@example.test', 'password': 'a-long-test-password'}
    assert client.post('/auth/login', headers={'Origin': 'https://evil.example.test'}, json=body).status_code == 403
    response = client.post('/auth/login', headers={'Origin': 'https://panel.example.test'}, json=body)
    assert response.status_code == 200
    assert 'secure' in response.headers['set-cookie'].lower()
    assert client.post('/auth/logout', headers={'Origin': 'https://panel.example.test'}).status_code == 403
    insecure = TestClient(app, base_url='http://panel.example.test')
    assert insecure.post('/auth/login', headers={'Origin': 'https://panel.example.test'}, json=body).status_code == 403


def test_enabling_mfa_revokes_preexisting_sessions_and_password_change_revokes_all(identity):
    from core.accounts import totp_code
    store, _, _, now = identity
    account = register(identity)
    old = store.login('alice@example.test', 'a-long-test-password', peer='127.0.0.1')
    seed = store.begin_totp(account['id'], 'a-long-test-password')['secret']
    recovery = store.enable_totp(account['id'], totp_code(seed, now[0]))['recovery_codes']
    assert store.authenticate_session(old['token']) is None
    current = store.login('alice@example.test', 'a-long-test-password', otp=recovery[0], peer='127.0.0.1')
    store.change_password(account['id'], 'a-long-test-password', 'a-new-long-test-password', recovery[1])
    assert store.authenticate_session(current['token']) is None
    with pytest.raises(HTTPException):
        store.login('alice@example.test', 'a-long-test-password', otp=recovery[2], peer='127.0.0.1')
    assert store.login('alice@example.test', 'a-new-long-test-password', otp=recovery[2], peer='127.0.0.1')


def test_concurrent_invite_redemption_and_otp_replay_have_one_winner(identity):
    from concurrent.futures import ThreadPoolExecutor
    from core.accounts import totp_code
    store, _, workspace, now = identity
    invitation = store.invite(workspace['id'], 'alice@example.test')
    def redeem(_):
        try:
            return store.register(invitation['token'], 'alice@example.test', 'a-long-test-password')
        except HTTPException:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        accounts = [x for x in executor.map(redeem, range(2)) if x]
    assert len(accounts) == 1
    seed = store.begin_totp(accounts[0]['id'], 'a-long-test-password')['secret']
    store.enable_totp(accounts[0]['id'], totp_code(seed, now[0]))
    now[0] += 30
    code = totp_code(seed, now[0])
    def login(_):
        try:
            return store.login('alice@example.test', 'a-long-test-password', otp=code, peer='127.0.0.1')
        except HTTPException:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sum(x is not None for x in executor.map(login, range(2))) == 1


def test_customer_cookie_mutations_cannot_select_another_workspace_or_echo_password(tmp_path, monkeypatch):
    monkeypatch.setenv('TP_WORKSPACES_DIR', str(tmp_path / 'customers'))
    monkeypatch.setenv('TP_SECRET_KEY', 'installation-test-key-for-accounts')
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(tmp_path / 'unused.db'))
    from apps.api.main import create_app
    app = create_app(sessionmaker(bind=create_engine('sqlite:///' + str(tmp_path / 'owner.db'))))
    registry, store = app.state.workspace_registry, app.state.accounts
    a, b = registry.create('A'), registry.create('B')
    token = store.invite(a['id'], 'alice@example.test')['token']
    store.register(token, 'alice@example.test', 'a-long-test-password')
    client = TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 23456))
    auth = client.post('/auth/login', json={'email': 'alice@example.test', 'password': 'a-long-test-password'}).json()
    body = {'name': 'owned', 'host': '8.8.8.8', 'host_key_fingerprint': 'a'*64, 'password': 'a-node-test-password'}
    assert client.post('/api/nodes', json=body).status_code == 403
    headers = {'X-CSRF-Token': auth['csrf'], 'Origin': 'http://127.0.0.1', 'X-Workspace-ID': b['id']}
    assert client.post('/api/nodes', headers=headers, json=body).status_code == 201
    assert len(client.get('/api/nodes', headers={'X-Workspace-ID': b['id']}).json()) == 1
    with registry._factory(b['id'])() as session:
        from core.models import Node
        assert session.query(Node).count() == 0
    assert client.post('/api/nodes', headers={**headers, 'Origin': 'https://evil.example.test'}, json=body).status_code == 403
    bad = 'private-validation-canary-'*20
    response = client.post('/auth/login', json={'email': 'alice@example.test', 'password': bad})
    assert response.status_code == 422
    assert bad not in response.text


def test_pending_totp_verification_is_rate_limited(identity, monkeypatch):
    store, _, _, now = identity
    account = register(identity)
    now[0] = 59
    import core.accounts as accounts
    original = accounts.secrets.token_bytes
    monkeypatch.setattr(accounts.secrets, 'token_bytes', lambda n: b'12345678901234567890' if n == 20 else original(n))
    store.begin_totp(account['id'], 'a-long-test-password')
    # RFC4226 counters0/1/2 are755224/287082/359152;000000 is invalid.
    for _ in range(10):
        with pytest.raises(HTTPException) as error:
            store.enable_totp(account['id'], '000000')
        assert error.value.status_code == 400
    with pytest.raises(HTTPException) as error:
        store.enable_totp(account['id'], '287082')
    assert error.value.status_code == 429
