"""Control-plane fault/admission tests; separate node-driver tests cover SSH actions."""
import copy
import base64
import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Base, Job, Node, ResourceAllocation, SecretReference
from core.workspaces import DEFAULT_LIMITS, workspace_context
from orchestrator.remote_nodes import encrypt_credentials

pytestmark = pytest.mark.unit_portable
ROUTE, CUSTOMER = 'a' * 32, 'f' * 32


class Nodes:
    def __init__(self):
        self.parent_pid, self.live, self.applies, self.stops = 42, {}, 0, 0
        self.lost_reply = self.foreign = False

    def inspect(self, context, spec, owned=None):
        return {'parent_pid': self.parent_pid, 'parent_config_sha256': hashlib.sha256(
            json.dumps(context['parent_runtime']['config'], sort_keys=True).encode()).hexdigest()}

    def observe(self, context, runtime):
        found = self.live.get(runtime['config']['id'])
        return copy.deepcopy(found) if found else {'observed': False}

    def apply(self, context, runtime, inspection, persist, previous=None):
        self.applies += 1
        persist(context['source']['id'], 'service', runtime['service'])
        found = {'observed': True, 'runtime': {'worker_pid': 900 + self.applies,
                 'revision': runtime['config']['revision'], 'config_sha256': runtime['config_sha256'],
                 'listening': True, 'password': 'must-never-be-public'}}
        found['reservation_ports'] = [runtime['config']['listen_port']]
        self.live[runtime['config']['id']] = found
        if self.lost_reply:
            self.lost_reply = False
            raise ConnectionError('reply lost after listener already active')
        return copy.deepcopy(found)

    def stop(self, context, runtime, alternative=None):
        if self.foreign:
            raise RuntimeError('foreign marker preserved')
        self.stops += 1
        self.live.pop(runtime['config']['id'], None)


@pytest.fixture
def control(tmp_path, monkeypatch):
    from orchestrator.service_forwards import ServiceForwardService
    monkeypatch.setenv('TP_SECRET_KEY', 'test-only-unique-service-installation-key')
    monkeypatch.setenv('TP_LOCK_DIR', str(tmp_path / 'locks'))
    engine = create_engine('sqlite:///' + str(tmp_path / 'workspace.db'), connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    nodes = Nodes()
    access = SimpleNamespace(allowed=True, enabled=True)
    def authorize(*args):
        if not access.allowed:
            raise HTTPException(402, 'new work requires entitlement')
    subscriptions = SimpleNamespace(authorize_operation=authorize,
        status=lambda *args: {'can_start_work': access.allowed, 'limits': dict(DEFAULT_LIMITS)},
        registry=SimpleNamespace(list=lambda: [{'id': CUSTOMER, 'enabled': access.enabled}]))
    routes = SimpleNamespace(monthly=None)
    service = ServiceForwardService(routes, subscriptions=subscriptions, node_driver=nodes)
    monkeypatch.setattr(service, 'kick', lambda *args: None)
    with factory() as session:
        secret = SecretReference(kind='mesh_runtime', ciphertext=encrypt_credentials({
            'directory': '/var/lib/tunnelpannel/mesh/' + ROUTE + '/gateway',
            'service': 'existing-parent-gateway', 'config': {
                'listen_host': '127.0.0.1', 'listen_port': 22001,
                'username': 'existing', 'password': 'existing-private-gateway-password',
                'traffic': {'rate_mbps': 32, 'quota_bytes': 0, 'max_connections': 8},
                'upstreams': [{'id': 'existing-member'}],
            }}))
        session.add(secret)
        session.flush()
        for index, identity in enumerate(('b' * 32, 'c' * 32)):
            ssh = SecretReference(kind='ssh', ciphertext=encrypt_credentials(
                {'auth_method': 'PASSWORD', 'secret': 'fixture-ssh-password'}))
            session.add(ssh)
            session.flush()
            session.add(Node(id=identity, name=identity, host='192.0.2.' + str(index + 1),
                             secret_ref=ssh.id, host_key_fingerprint=str(index + 1) * 64))
        session.add(Job(id=ROUTE, kind='mesh_route', state='COMMITTED', payload={
            'source': 'b' * 32, 'destination': 'c' * 32, 'runtime_secret_id': secret.id,
            'methods': ['IP4IN6'], 'workspace_id': CUSTOMER}))
        session.commit()
    token = workspace_context.set({'id': CUSTOMER, 'factory': factory, 'limits': dict(DEFAULT_LIMITS)})
    try:
        yield service, factory, nodes, access
    finally:
        workspace_context.reset(token)
        engine.dispose()


def body(**changes):
    return {'name': 'service', 'route_id': ROUTE, 'bind_host': '127.0.0.1', 'bind_port': 25001,
            'target_host': '127.0.0.1', 'target_port': 4949, **changes}


def create(control, **changes):
    service, factory, _, _ = control
    value = body(**changes)
    ticket = service.preflight(factory, value, DEFAULT_LIMITS)
    request = {**value, 'request_id': 'd' * 32, 'preflight_id': ticket['id'],
               'preflight_token': ticket['token']}
    return service.create(factory, request, DEFAULT_LIMITS), request


def edit_request(control, identity, **changes):
    service, factory, _, _ = control
    value = body(**changes)
    ticket = service.preflight(factory, {**value, 'service_id': identity, 'expected_revision': 1}, DEFAULT_LIMITS)
    return {**value, 'expected_revision': 1, 'request_id': 'e' * 32,
            'preflight_id': ticket['id'], 'preflight_token': ticket['token']}


def test_update_keeps_old_settings_until_verified_and_preserves_parent_and_history(control):
    from orchestrator.remote_nodes import decrypt_credentials
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    with factory() as session:
        parent = copy.deepcopy(session.get(Job, ROUTE).payload)
        old_secret = session.get(Job, identity).payload['runtime_secret_id']
    request = edit_request(control, identity, bind_port=25002, name='edited service')
    assert service.update(factory, identity, request, DEFAULT_LIMITS) == identity
    with factory() as session:
        row = session.get(Job, identity)
        assert row.state == 'UPDATING' and row.payload['bind_port'] == 25001 and row.payload['revision'] == 1
        assert row.payload['runtime_secret_id'] == old_secret
        assert row.payload['pending_runtime_secret_id'] != old_secret
        checkpoint = session.get(SecretReference, row.payload['operation']['checkpoint_secret_id'])
        assert decrypt_credentials(checkpoint.ciphertext)['spec']['bind_port'] == 25001
        assert len(list(session.query(ResourceAllocation).filter(ResourceAllocation.kind == 'tcp_port',
            ResourceAllocation.released_at.is_(None)))) == 2
    service._run(factory, identity)
    assert service.update(factory, identity, request, DEFAULT_LIMITS) == identity
    result = service.observe(factory, identity)
    assert result['state'] == 'ACTIVE' and result['revision'] == 2 and result['bind_port'] == 25002
    assert nodes.applies == 2
    with factory() as session:
        row = session.get(Job, identity)
        assert 'pending_runtime_secret_id' not in row.payload
        assert session.get(SecretReference, old_secret) is not None
        assert session.get(Job, ROUTE).payload == parent
        assert [row.key for row in session.query(ResourceAllocation).filter(ResourceAllocation.kind == 'tcp_port',
            ResourceAllocation.released_at.is_(None))] == ['25002']


def test_update_revision_stale_preflight_and_unpaid_worker_cannot_change_running_service(control):
    service, factory, nodes, access = control
    identity, _ = create(control)
    service._run(factory, identity)
    request = edit_request(control, identity, target_port=4950)
    with pytest.raises(HTTPException):
        service.update(factory, identity, {**request, 'expected_revision': 2}, DEFAULT_LIMITS)
    assert nodes.applies == 1
    service.update(factory, identity, request, DEFAULT_LIMITS)
    access.allowed = False
    service._run(factory, identity)
    assert nodes.applies == 1 and service.observe(factory, identity)['state'] == 'NEEDS_RECOVERY'
    assert service.observe(factory, identity)['target_port'] == 4949


def test_recovery_adopts_new_generation_after_lost_edit_reply_without_restart(control):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    service.update(factory, identity, edit_request(control, identity, target_port=4950), DEFAULT_LIMITS)
    nodes.lost_reply = True
    service._run(factory, identity)
    assert nodes.applies == 2 and service.observe(factory, identity)['revision'] == 2
    with factory() as session:
        row = session.get(Job, identity)
        assert row.state == 'ACTIVE'
    service.recover(factory)
    assert nodes.applies == 2


def test_interrupted_edit_requires_fresh_explicit_preflight_and_preserves_old_runtime(control):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    request = edit_request(control, identity, target_port=4950)
    service.update(factory, identity, request, DEFAULT_LIMITS)
    service.recover(factory)  # Queued/lost operation has not reached the source.
    assert nodes.applies == 1 and service.observe(factory, identity)['state'] == 'NEEDS_RECOVERY'
    with pytest.raises(HTTPException):
        service.reconcile(factory, identity, request, DEFAULT_LIMITS)
    fresh = edit_request(control, identity, target_port=4950)
    fresh['request_id'] = '9' * 32
    service.reconcile(factory, identity, fresh, DEFAULT_LIMITS)
    service._run(factory, identity)
    assert service.observe(factory, identity)['revision'] == 2 and nodes.applies == 2


def test_stop_racing_edit_cleans_only_the_known_generations_and_never_reactivates(control, monkeypatch):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    service.update(factory, identity, edit_request(control, identity, bind_port=25002), DEFAULT_LIMITS)
    apply = nodes.apply
    def apply_then_stop(*args, **kwargs):
        result = apply(*args, **kwargs)
        service.stop(factory, identity)
        return result
    monkeypatch.setattr(nodes, 'apply', apply_then_stop)
    service._run(factory, identity)
    assert service.observe(factory, identity)['state'] == 'STOPPED'
    assert nodes.stops == 1 and not nodes.live
    with factory() as session:
        assert session.get(Job, ROUTE).state == 'COMMITTED'
        assert not list(session.query(ResourceAllocation).filter(ResourceAllocation.released_at.is_(None)))


def test_new_edit_admitted_while_prior_worker_exits_is_dispatched_once(control, monkeypatch):
    import orchestrator.service_forwards as module
    service, factory, nodes, _ = control
    identity, _ = create(control)
    targets = []
    class Thread:
        def __init__(self, *, target, **kwargs):
            self.target = target
        def start(self):
            targets.append(self.target)
    monkeypatch.setattr(module.threading, 'Thread', Thread)
    monkeypatch.setattr(service, 'kick', module.ServiceForwardService.kick.__get__(service))
    run = service._run
    queued = []
    def first_then_edit(*args):
        run(*args)
        if not queued:
            queued.append(True)
            service.update(factory, identity, edit_request(control, identity, target_port=4950), DEFAULT_LIMITS)
    monkeypatch.setattr(service, '_run', first_then_edit)
    service.kick(factory, identity)
    targets[0]()
    assert len(targets) == 2
    targets[1]()
    assert len(targets) == 2 and nodes.applies == 2
    assert service.observe(factory, identity)['revision'] == 2


def test_simultaneous_customer_admissions_share_one_transactional_limit(control):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    service, factory, _, _ = control
    barrier = threading.Barrier(2)
    requests = []
    for number in range(2):
        value = body(bind_port=25001 + number)
        ticket = service.preflight(factory, value, DEFAULT_LIMITS)
        requests.append({**value, 'preflight_id': ticket['id'], 'preflight_token': ticket['token'],
                         'request_id': str(number + 1) * 32})
    def admit(request):
        token = workspace_context.set({'id': CUSTOMER, 'factory': factory, 'limits': dict(DEFAULT_LIMITS)})
        try:
            barrier.wait(timeout=5)
            try:
                return service.create(factory, request, {**DEFAULT_LIMITS, 'max_active_routes': 1})
            except HTTPException as error:
                return error.status_code
        finally:
            workspace_context.reset(token)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(admit, requests))
    assert sum(isinstance(value, str) for value in results) == 1 and results.count(409) == 1
    with factory() as session:
        assert session.query(Job).filter(Job.kind == 'mesh_service_forward').count() == 1


def test_failed_update_commit_releases_dispatch_fence_and_preserves_old_settings(control, monkeypatch):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    request = edit_request(control, identity, bind_port=25002)
    commit = factory.class_.commit
    def fail_operation(session):
        if any(isinstance(row, Job) and row.kind == 'service_forward_operation' for row in session.identity_map.values()):
            raise RuntimeError('injected update commit failure')
        return commit(session)
    monkeypatch.setattr(factory.class_, 'commit', fail_operation)
    with pytest.raises(RuntimeError):
        service.update(factory, identity, request, DEFAULT_LIMITS)
    assert not service._launching
    with factory() as session:
        assert session.get(Job, identity).state == 'ACTIVE'
        assert session.get(Job, identity).payload['bind_port'] == 25001
    assert nodes.applies == 1


def test_remote_reinspection_does_not_hold_workspace_sqlite_writer_lock(control, monkeypatch):
    from sqlalchemy import text
    service, factory, nodes, _ = control
    ticket = service.preflight(factory, body(), DEFAULT_LIMITS)
    inspect = nodes.inspect
    def inspect_with_other_writer(*args, **kwargs):
        with factory() as session:
            session.execute(text('PRAGMA busy_timeout=1'))
            session.add(Job(kind='independent_operation', state='PASS', payload={}))
            session.commit()
        return inspect(*args, **kwargs)
    monkeypatch.setattr(nodes, 'inspect', inspect_with_other_writer)
    request = {**body(), 'request_id': '8' * 32, 'preflight_id': ticket['id'], 'preflight_token': ticket['token']}
    identity = service.create(factory, request, DEFAULT_LIMITS)
    service._run(factory, identity)
    service.update(factory, identity, edit_request(control, identity, target_port=4950), DEFAULT_LIMITS)
    service.recover(factory)
    fresh = edit_request(control, identity, target_port=4950)
    fresh['request_id'] = '7' * 32
    service.reconcile(factory, identity, fresh, DEFAULT_LIMITS)


def test_changed_pinned_endpoint_invalidates_old_preflight_without_dispatch(control):
    service, factory, nodes, _ = control
    ticket = service.preflight(factory, body(), DEFAULT_LIMITS)
    with factory() as session:
        session.get(Node, 'b' * 32).host = '192.0.2.33'
        session.commit()
    with pytest.raises(HTTPException) as error:
        service.create(factory, {**body(), 'request_id': '8' * 32, 'preflight_id': ticket['id'],
            'preflight_token': ticket['token']}, DEFAULT_LIMITS)
    assert error.value.status_code == 409 and nodes.applies == 0


def test_preflight_create_replay_and_recovery_preserve_parent_and_hide_secrets(control):
    service, factory, nodes, _ = control
    with factory() as session:
        before = copy.deepcopy(session.get(Job, ROUTE).payload)
    identity, request = create(control)
    assert service.create(factory, request, DEFAULT_LIMITS) == identity
    service._run(factory, identity)
    service._run(factory, identity)
    result = service.observe(factory, identity)
    assert result['state'] == 'ACTIVE' and result['observed']
    assert nodes.applies == 1 and result['runtime']['worker_pid'] == 901
    assert 'password' not in json.dumps(result) and 'runtime_secret_id' not in result
    with factory() as session:
        assert session.get(Job, ROUTE).payload == before
        assert session.get(Job, ROUTE).state == 'COMMITTED'


def test_worker_adopts_active_candidate_after_lost_reply_without_second_apply(control):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    nodes.lost_reply = True
    service._run(factory, identity)
    assert service.observe(factory, identity)['state'] == 'ACTIVE'
    with factory() as session:
        job = session.get(Job, identity)
        job.state = 'APPLYING'
        session.commit()
    service.recover(factory)
    service._run(factory, identity)
    assert nodes.applies == 1
    assert service.observe(factory, identity)['runtime']['worker_pid'] == 901


def test_stale_route_identity_and_expired_token_do_not_dispatch(control):
    service, factory, nodes, _ = control
    ticket = service.preflight(factory, body(), DEFAULT_LIMITS)
    nodes.parent_pid = 43
    with pytest.raises(HTTPException) as error:
        service.create(factory, {**body(), 'request_id': 'd' * 32, 'preflight_id': ticket['id'],
                                  'preflight_token': ticket['token']}, DEFAULT_LIMITS)
    assert error.value.status_code == 409 and nodes.applies == 0
    nodes.parent_pid = 42
    service.clock = lambda: 10**12
    with pytest.raises(HTTPException) as error:
        service.create(factory, {**body(), 'request_id': 'd' * 32, 'preflight_id': ticket['id'],
                                  'preflight_token': ticket['token']}, DEFAULT_LIMITS)
    assert error.value.status_code == 409


def test_changed_body_token_and_plan_limits_cannot_create_extra_forwards(control):
    service, factory, nodes, _ = control
    ticket = service.preflight(factory, body(), DEFAULT_LIMITS)
    request = {**body(), 'request_id': 'd' * 32, 'preflight_id': ticket['id'], 'preflight_token': ticket['token']}
    for change in ({'target_port': 4950}, {'preflight_token': '0' * 64}):
        with pytest.raises(HTTPException) as error:
            service.create(factory, {**request, **change}, DEFAULT_LIMITS)
        assert error.value.status_code == 409
    identity = service.create(factory, request, {**DEFAULT_LIMITS, 'max_active_routes': 1})
    second = body(bind_port=25002)
    ticket = service.preflight(factory, second, DEFAULT_LIMITS)
    with pytest.raises(HTTPException) as error:
        service.create(factory, {**second, 'request_id': 'e' * 32, 'preflight_id': ticket['id'],
                                  'preflight_token': ticket['token']}, {**DEFAULT_LIMITS, 'max_active_routes': 1})
    assert error.value.status_code == 409 and nodes.applies == 0
    assert service.observe(factory, identity)['state'] == 'APPLYING'


def test_disabled_unpaid_or_parent_pending_migration_cannot_start_service(control):
    service, factory, nodes, access = control
    access.allowed = False
    with pytest.raises(HTTPException) as error:
        service.preflight(factory, body(), DEFAULT_LIMITS)
    assert error.value.status_code == 402
    access.allowed, access.enabled = True, False
    with pytest.raises(HTTPException) as error:
        service.preflight(factory, body(), DEFAULT_LIMITS)
    assert error.value.status_code == 403
    access.enabled = True
    with factory() as session:
        job = session.get(Job, ROUTE)
        job.payload = {**job.payload, 'accounting_migration': {'phase': 'pending'}}
        session.commit()
    with pytest.raises(HTTPException) as error:
        service.preflight(factory, body(), DEFAULT_LIMITS)
    assert error.value.status_code == 409 and nodes.applies == 0


def test_stop_only_owned_forward_retains_parent_and_refuses_foreign_marker(control):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    nodes.foreign = True
    service.stop(factory, identity)
    service._run(factory, identity)
    assert nodes.stops == 0 and service.observe(factory, identity)['state'] != 'STOPPED'
    with factory() as session:
        assert session.query(ResourceAllocation).filter_by(released_at=None).count() > 0
    nodes.foreign = False
    service.stop(factory, identity)
    service._run(factory, identity)
    assert nodes.stops == 1 and service.observe(factory, identity)['state'] == 'STOPPED'
    with factory() as session:
        assert session.get(Job, ROUTE).state == 'COMMITTED'
        assert session.query(ResourceAllocation).filter_by(released_at=None).count() == 0


def test_parent_dependency_hook_fails_closed_before_original_cleanup(control, monkeypatch):
    from orchestrator.mesh_routes import RouteService
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service._run(factory, identity)
    parent = RouteService()
    parent.forward_dependencies = service
    called = []
    monkeypatch.setattr('orchestrator.mesh_reconcile.reconcile_benchmark', lambda *args: called.append('parent-cleanup'))
    with factory() as session:
        job = session.get(Job, ROUTE)
        job.state = 'STOPPING'
        session.commit()
    nodes.foreign = True
    parent._run(factory, ROUTE)
    assert not called and nodes.stops == 0
    with factory() as session:
        assert session.get(Job, ROUTE).state == 'FAILED'
    nodes.foreign = False
    monkeypatch.setattr(parent, 'kick', lambda *args: None)
    parent.stop(factory, ROUTE)
    # Prevent a real background thread in this deterministic control test.
    parent._run(factory, ROUTE)
    assert nodes.stops == 1 and called


def test_stop_arriving_during_activation_cannot_be_overwritten_by_active_commit(control, monkeypatch):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    actual = nodes.apply
    def stop_after_source_apply(*args, **kwargs):
        result = actual(*args, **kwargs)
        service.stop(factory, identity)
        return result
    monkeypatch.setattr(nodes, 'apply', stop_after_source_apply)
    service._run(factory, identity)
    assert nodes.stops == 1
    assert service.observe(factory, identity)['state'] == 'STOPPED'


def test_recovery_never_reinstalls_an_unobserved_pending_candidate(control):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    service.recover(factory)
    assert nodes.applies == 0
    assert service.observe(factory, identity)['state'] == 'NEEDS_RECOVERY'


def test_recovery_does_not_steal_a_queued_current_process_worker(control):
    service, factory, nodes, _ = control
    identity, _ = create(control)
    key = str(factory.kw['bind'].url) + identity
    service._threads[key] = object()
    try:
        service.recover(factory)
    finally:
        service._threads.pop(key)
    assert nodes.applies == 0
    assert service.observe(factory, identity)['state'] == 'APPLYING'


def test_worker_rechecks_entitlement_before_source_mutation(control):
    service, factory, nodes, access = control
    identity, _ = create(control)
    access.allowed = False
    service._run(factory, identity)
    assert nodes.applies == 0 and not nodes.live
    assert service.observe(factory, identity)['state'] == 'NEEDS_RECOVERY'


def test_two_node_aliases_with_same_physical_host_key_are_not_a_service_pair(control):
    service, factory, nodes, _ = control
    with factory() as session:
        node = session.get(Node, 'c' * 32)
        node.host_key_fingerprint = 'SHA256:' + base64.b64encode(bytes.fromhex('1' * 64)).decode().rstrip('=')
        session.commit()
    with pytest.raises(HTTPException) as error:
        service.preflight(factory, body(), DEFAULT_LIMITS)
    assert error.value.status_code == 409 and nodes.applies == 0


def test_queued_service_port_reservation_is_a_conflict_not_a_server_error(control):
    service, factory, nodes, _ = control
    create(control)
    ticket = service.preflight(factory, body(), DEFAULT_LIMITS)
    with pytest.raises(HTTPException) as error:
        service.create(factory, {**body(), 'request_id': 'e' * 32, 'preflight_id': ticket['id'],
                                  'preflight_token': ticket['token']}, DEFAULT_LIMITS)
    assert error.value.status_code == 409 and nodes.applies == 0
    with factory() as session:
        assert session.query(Job).filter_by(kind='mesh_service_forward').count() == 1
