"""Fresh inventory and own-unit safety, without contacting real SSH servers."""
import copy
import json
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit_portable


def inventory(**changes):
    return {'schema': 1, 'complete': True, 'errors': [], 'listeners': [],
            'reserved_ranges': {}, 'networks': {
                '-4_addresses': [{'addr_info': [{'local': '192.0.2.1'}, {'local': '127.0.0.1'}]}],
                '-6_addresses': [{'addr_info': [{'local': '2001:db8::1'}, {'local': '::1'}]}]}, **changes}


def spec(**changes):
    return {'bind_host': '127.0.0.1', 'bind_port': 25001, 'target_host': '127.0.0.1',
            'target_port': 4949, 'source_cidrs': [], 'allow_public': False, **changes}


@pytest.fixture
def driver_fixture(tmp_path, monkeypatch):
    from orchestrator.service_forward_nodes import ForwardNodeDriver, prepare_runtime
    from test_service_forward_node_helper import descriptor
    from orchestrator.service_forward_node_helper import fingerprint
    monkeypatch.setenv('TP_LOCK_DIR', str(tmp_path / 'locks'))
    runtime, _ = descriptor()
    runtime['config']['target_port'] = 4949
    runtime['config_sha256'] = fingerprint(runtime['config'])
    runtime = prepare_runtime(runtime)
    context = {'route_id': runtime['config']['route_id'],
        'source': {'id': 'a' * 32, 'host': '192.0.2.1', 'host_key_fingerprint': '1' * 64,
                   'port': 2222, 'ssh_username': 'root'},
        'destination': {'id': 'b' * 32, 'host': '192.0.2.2', 'host_key_fingerprint': '2' * 64,
                        'port': 2223, 'ssh_username': 'root'},
        'access': {'a' * 32: {'secret': 'source-SSH-not-forwarded'},
                   'b' * 32: {'secret': 'destination-SSH-not-forwarded'}},
        'parent_runtime': {'service': 'tpmesh-123456789-0-gateway', 'config': {
            'listen_port': 22001, 'password': 'parent-credential-not-inspection', 'monthly': {'key': 'private'}}},
        'forbidden_ports': [26009]}
    state = SimpleNamespace(pid=42, live={}, events=[], remotes=[], incomplete=False)
    class Remote:
        def __init__(self, endpoint, access):
            assert access == context['access'][endpoint['id']]
            self.endpoint = endpoint
            state.remotes.append(self)
        def connect(self):
            return self
        def close(self):
            state.events.append(('close', self.endpoint['id']))
        def forward_call(self, request):
            state.events.append((self.endpoint['id'], copy.deepcopy(request)))
            assert 'SSH-not-forwarded' not in json.dumps(request)
            action = request['action']
            if action == 'parent':
                assert self.endpoint == context['source']
                return {'parent_pid': state.pid, 'parent_config_sha256': request['parent']['config_sha256']}
            if action == 'controls':
                return [8710]
            if action == 'observe':
                return state.live.get(request['runtime']['config']['id'], {'observed': False})
            if action == 'socket':
                return {'verified': True, 'port': runtime['config']['listen_port'], 'pid': 1357}
            if action == 'apply':
                assert ('persist', 'service', runtime['service']) in state.events
                row = {'observed': True, 'runtime': {'listening': True, 'worker_pid': 1357,
                    'revision': runtime['config']['revision'], 'config_sha256': runtime['config_sha256']}}
                state.live[runtime['config']['id']] = row
                return row
            if action == 'stop':
                return {'stopped': True}
            raise AssertionError(action)
    def scanner(remote):
        return inventory(complete=not state.incomplete, listeners=[] if remote.endpoint == context['source'] else
                         [{'proto': 'TCP', 'addr': '127.0.0.1', 'port': 4949, 'proc': 'xray', 'source': 'socket'}])
    return ForwardNodeDriver(remote_factory=Remote, scanner=scanner), context, runtime, state


def test_driver_rechecks_pinned_hosts_and_persists_ownership_before_source_dispatch(driver_fixture):
    driver, context, runtime, state = driver_fixture
    value = spec(bind_port=runtime['config']['listen_port'])
    inspection = driver.inspect(context, value)
    assert 'private' not in json.dumps(inspection) and 'credential' not in json.dumps(inspection)
    persist = lambda node, kind, key: state.events.append(('persist', kind, key))
    result = driver.apply(context, runtime, inspection, persist)
    assert result['observed'] and driver.observe(context, runtime)['observed']
    driver.stop(context, runtime)
    assert any(event[0] == 'persist' for event in state.events)
    # The exit node never receives the source gateway authentication or runtime.
    destination_requests = [event[1] for event in state.events
        if event[0] == context['destination']['id'] and isinstance(event[1], dict)]
    assert destination_requests and all(row == {'action': 'controls'} for row in destination_requests)


def test_driver_refuses_changed_parent_or_incomplete_inventory_before_dispatch(driver_fixture):
    from orchestrator.service_forward_nodes import ForwardBlocked
    driver, context, runtime, state = driver_fixture
    inspection = driver.inspect(context, spec(bind_port=runtime['config']['listen_port']))
    state.pid = 43
    with pytest.raises(ForwardBlocked):
        driver.apply(context, runtime, inspection, lambda *args: None)
    assert not any(isinstance(event[1], dict) and event[1].get('action') == 'apply' for event in state.events)
    state.incomplete = True
    with pytest.raises(ForwardBlocked):
        driver.inspect(context, spec())


@pytest.mark.parametrize('source', ['socket', 'container'])
@pytest.mark.parametrize('address', ['0.0.0.0', '::', '127.0.0.1', '192.0.2.1'])
def test_source_conflict_in_any_family_or_container_never_relocates_requested_port(source, address):
    from orchestrator.service_forward_nodes import ForwardBlocked, validate_source
    report = inventory(listeners=[{'proto': 'TCP', 'addr': address, 'port': 25001,
                                    'proc': 'foreign', 'source': source}])
    before = copy.deepcopy(report)
    with pytest.raises(ForwardBlocked) as error:
        validate_source(report, spec())
    assert error.value.code == 'port_in_use' and report == before


def test_source_reservations_and_missing_inventory_fail_closed():
    from orchestrator.service_forward_nodes import ForwardBlocked, validate_source
    for report in (inventory(complete=False), inventory(errors=['docker_ports']),
                   inventory(reserved_ranges={'TCP': [[25000, 25100]]})):
        with pytest.raises(ForwardBlocked):
            validate_source(report, spec())
    with pytest.raises(ForwardBlocked):
        validate_source(inventory(), spec(bind_host='192.0.2.8', allow_public=True, source_cidrs=['192.0.2.0/24']))
    assert validate_source(inventory(), spec(bind_host='192.0.2.1', allow_public=True,
                                             source_cidrs=['192.0.2.0/24'])) is None


def test_source_can_ignore_one_listener_only_with_verified_exact_owned_identity():
    from orchestrator.service_forward_nodes import ForwardBlocked, validate_source
    row = {'proto': 'TCP', 'addr': '127.0.0.1', 'port': 25001, 'proc': 'python3', 'source': 'socket'}
    report = inventory(listeners=[row])
    for proof in (None, {'verified': False, 'port': 25001, 'pid': 42},
                  {'verified': True, 'port': 25002, 'pid': 42},
                  {'verified': True, 'port': 25001, 'pid': 0}):
        with pytest.raises(ForwardBlocked):
            validate_source(report, spec(), owned=proof)
    proof = {'verified': True, 'port': 25001, 'pid': 42}
    assert validate_source(report, spec(), owned=proof) is None
    with pytest.raises(ForwardBlocked):
        validate_source(inventory(listeners=[row, {**row, 'source': 'container'}]), spec(), owned=proof)


def test_target_requires_exit_owned_address_and_real_service_not_control_port():
    from orchestrator.service_forward_nodes import ForwardBlocked, validate_target
    report = inventory(listeners=[{'proto': 'TCP', 'addr': '0.0.0.0', 'port': 4949,
                                    'proc': 'xray', 'source': 'socket'}])
    assert validate_target(report, spec(), forbidden_ports={22, 8710}) is None
    for value in (spec(target_host='192.0.2.8'), spec(target_port=22), spec(target_port=8710)):
        with pytest.raises(ForwardBlocked):
            validate_target(report, value, forbidden_ports={22, 8710})
    with pytest.raises(ForwardBlocked):
        validate_target(inventory(), spec())
    # A user inbound on443 is allowed; source-listener NEVER_PORTS is not a target blanket ban.
    report['listeners'][0]['port'] = 443
    assert validate_target(report, spec(target_port=443), forbidden_ports={22, 8710}) is None


def test_unit_uses_private_credentials_and_cannot_start_or_restart_parent():
    from orchestrator.service_forward_nodes import unit_text
    runtime = {'config': {'id': 'a' * 32}, 'service': 'tpforward-' + 'a' * 32,
               'directory': '/etc/tunnelpannel-forwards/' + 'a' * 32,
               'code_directory': '/opt/tunnelpannel-forwards/' + 'a' * 32,
               'state_path': '/var/lib/tunnelpannel-forward-' + 'a' * 32 + '/state.json'}
    unit = unit_text(runtime)
    for value in ('DynamicUser=yes', 'LoadCredential=forward.json:', 'ProtectSystem=strict',
                  'NoNewPrivileges=yes', 'StandardOutput=null', 'StandardError=null',
                  '--config %d/forward.json', '--state ' + runtime['state_path']):
        assert value in unit
    assert 'Requires=' not in unit and 'BindsTo=' not in unit
    assert 'existing-parent' not in unit and 'password' not in unit
    assert '/var/lib/tunnelpannel/' not in unit
