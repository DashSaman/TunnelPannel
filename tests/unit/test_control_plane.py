"""The durable management container must never become a tunnel execution node."""
import socket

import pytest


@pytest.fixture
def control_plane(monkeypatch):
    monkeypatch.setenv('TP_CONTROL_PLANE_ONLY', '1')
    monkeypatch.setenv('TP_CONTROLLER_EXCLUDED_HOSTS', '91.107.138.246,172.30.0.1')
    monkeypatch.setenv('TP_RETIRED_NODE_HOSTS', '65.109.209.194,65.109.213.64')


@pytest.mark.parametrize('host', ['127.0.0.1', '::1', 'localhost', '0.0.0.0',
                                    '169.254.169.254', '91.107.138.246', '65.109.209.194'])
def test_management_and_retired_hosts_rejected_before_authentication(control_plane, host):
    from core.control_plane import remote_target
    with pytest.raises(ValueError):
        remote_target(host, 22)


def test_hostname_is_resolved_once_and_numeric_result_pinned(control_plane, monkeypatch):
    from core.control_plane import remote_target
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('203.0.113.12', 22))])
    assert remote_target('customer.example', 22) == '203.0.113.12'
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('91.107.138.246', 22))])
    with pytest.raises(ValueError):
        remote_target('alias.example', 22)


def test_normal_node_installs_keep_existing_endpoint_behavior(monkeypatch):
    from core.control_plane import remote_target
    monkeypatch.delenv('TP_CONTROL_PLANE_ONLY', raising=False)
    assert remote_target('registered.internal', 22) == 'registered.internal'


def test_management_mode_requires_explicit_excluded_host_configuration(monkeypatch):
    from core.control_plane import remote_target
    monkeypatch.setenv('TP_CONTROL_PLANE_ONLY', '1')
    monkeypatch.delenv('TP_CONTROLLER_EXCLUDED_HOSTS', raising=False)
    with pytest.raises(ValueError):
        remote_target('203.0.113.12', 22)


def test_node_channel_uses_guard_before_sending_any_credentials(control_plane, monkeypatch):
    from orchestrator.remote_nodes import NodeRemote
    calls=[]
    monkeypatch.setattr('paramiko.SSHClient.connect', lambda *a, **k: calls.append(k))
    remote=NodeRemote({'host':'91.107.138.246','port':22,'ssh_username':'root',
                       'host_key_fingerprint':'a'*64}, {'auth_method':'PASSWORD','secret':'test-only'})
    with pytest.raises(ValueError):
        remote.connect()
    assert calls == []


def test_offline_restore_preserves_accounts_payloads_and_history_without_replay(control_plane, tmp_path):
    import sqlite3
    from scripts.control_plane_admin import initialize
    from core.accounts import AccountStore
    from core.models import Job, OperationPolicy
    from core.workspaces import WorkspaceRegistry
    data=tmp_path/'data'
    owner={'username':'owner_fixture','password':'local-owner-fixture-123'}
    initialize(data,owner)
    registry=WorkspaceRegistry(data/'workspaces')
    customer=registry.create('Restored customer')
    store=AccountStore(registry)
    account=store.create_managed(customer['id'],username='customer_fixture',password='local-customer-fixture-123')
    with sqlite3.connect(data/'workspaces/registry.db') as db:
        original_hash=db.execute('SELECT password_hash FROM accounts WHERE id=?',(account['id'],)).fetchone()[0]
    factory=registry._factory(customer['id'])
    with factory() as session:
        session.add_all([Job(id='a'*32,kind='mesh_campaign',state='RUNNING',payload={'marker':'retain'}),
                         Job(id='b'*32,kind='mesh_route',state='COMMITTED',payload={'config':'retain'}),
                         OperationPolicy(enabled=True)])
        session.commit()
    result=initialize(data,owner,retire_pending=True)
    assert result['historical_workers_replayed'] is False
    with factory() as session:
        assert session.get(Job,'a'*32).state=='INTERRUPTED'
        assert session.get(Job,'a'*32).payload=={'marker':'retain'}
        assert session.get(Job,'b'*32).state=='COMMITTED'
        assert session.get(Job,'b'*32).payload=={'config':'retain'}
        assert session.get(OperationPolicy,'monitor').enabled is False
    with sqlite3.connect(data/'workspaces/registry.db') as db:
        assert db.execute('SELECT password_hash FROM accounts WHERE id=?',(account['id'],)).fetchone()[0]==original_hash
    assert store.login('owner_fixture',owner['password'],peer='127.0.0.1')['account']['role']=='SUPER_ADMIN'
