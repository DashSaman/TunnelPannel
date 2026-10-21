"""Typed source-helper inputs before any privileged filesystem operation."""
import base64
import copy
import hashlib
import json
import os
import stat
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.unit_portable


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def descriptor():
    from orchestrator.service_forward_nodes import unit_text
    from orchestrator.service_forward_runtime import validate_runtime
    from test_service_forward_runtime import configuration
    config = validate_runtime(configuration())
    identity = config['id']
    runtime = {'config': config, 'config_sha256': fingerprint(config), 'owner': 'b' * 64,
               'deployment_id': 'd' * 32, 'nonce': 123456789, 'service': 'tpforward-' + identity,
               'directory': '/etc/tunnelpannel-forwards/' + identity,
               'code_directory': '/opt/tunnelpannel-forwards/' + identity,
               'state_path': '/var/lib/tunnelpannel-forward-' + identity + '/state.json'}
    programs = {name: b'pass\n' for name in ('relay.py', 'mesh_gateway.py', 'service_forward_protocol.py')}
    runtime['program_sha256'] = {name: hashlib.sha256(value).hexdigest() for name, value in programs.items()}
    runtime['unit_text'] = unit_text(runtime)
    runtime['unit_sha256'] = hashlib.sha256(runtime['unit_text'].encode()).hexdigest()
    return runtime, {name: base64.b64encode(value).decode() for name, value in programs.items()}


def test_helper_metadata_is_fixed_to_own_namespaces_and_verified_bytes():
    from orchestrator.service_forward_node_helper import validate_metadata, validate_programs
    runtime, programs = descriptor()
    assert validate_metadata(runtime)['service'] == runtime['service']
    assert validate_programs(runtime, programs) == {name: b'pass\n' for name in programs}


@pytest.mark.parametrize('change', [
    {'owner': 'not-an-owner'}, {'nonce': True}, {'nonce': 0}, {'deployment_id': '../foreign'},
    {'service': 'tunnelpannel-api'}, {'directory': '/etc/tunnelpannel'},
    {'directory': '/var/lib/tunnelpannel/private-forward'},
    {'code_directory': '/opt/tunnelpannel'}, {'state_path': '/var/lib/tunnelpannel/state.json'},
    {'config_sha256': '0' * 64}, {'unit_sha256': '0' * 64},
    {'program_sha256': {'../foreign.py': 'a' * 64}},
    {'ssh_credentials': {'secret': 'controller-ssh-secret-must-not-be-forwarded'}},
])
def test_helper_rejects_foreign_paths_and_unbound_ownership_before_io(change):
    from orchestrator.service_forward_node_helper import validate_metadata
    runtime, _ = descriptor()
    with pytest.raises(ValueError):
        validate_metadata({**runtime, **change})


def test_helper_rejects_changed_unknown_or_uncompilable_programs():
    from orchestrator.service_forward_node_helper import validate_programs
    runtime, programs = descriptor()
    changed = copy.deepcopy(programs)
    changed['relay.py'] = base64.b64encode(b'raise SystemExit(1)\n').decode()
    for value in (changed, {**programs, '../outside.py': programs['relay.py']},
                  {**programs, 'relay.py': 'not base64'}):
        with pytest.raises(ValueError):
            validate_programs(runtime, value)
    bad = b'def broken(:\n'
    runtime['program_sha256']['relay.py'] = hashlib.sha256(bad).hexdigest()
    with pytest.raises(ValueError):
        validate_programs(runtime, {**programs, 'relay.py': base64.b64encode(bad).decode()})


def test_ownership_paths_cannot_be_selected_by_request_metadata():
    from orchestrator.service_forward_node_helper import ownership_paths
    runtime, _ = descriptor()
    paths = ownership_paths(runtime)
    identity = runtime['config']['id']
    assert paths['certificate'] == '/etc/tunnelpannel-forwards/.owner-' + identity + '.json'
    assert paths['directory'] == runtime['directory']
    assert paths['unit'] == '/etc/systemd/system/' + runtime['service'] + '.service'
    assert paths['book'] == '/var/lib/tunnelpannel-engine-reservations/tp-123456789-0.json'
    assert paths['book_directory'] == '/var/lib/tunnelpannel-engine-reservations/.tpforward-' + identity
    assert paths['key_directory'] == '/etc/tunnelpannel-forward-rescue-keys/' + identity


def test_privileged_artifacts_require_owner_kind_and_private_permissions():
    from orchestrator.service_forward_node_helper import require_owned
    def info(mode, uid=0):
        return SimpleNamespace(st_mode=mode, st_uid=uid)
    assert require_owned(info(stat.S_IFREG | 0o600), uid=0) is None
    assert require_owned(info(stat.S_IFREG | 0o644), private=False, uid=0) is None
    assert require_owned(info(stat.S_IFDIR | 0o700), directory=True, uid=0) is None
    for value, options in (
        (info(stat.S_IFLNK | 0o777), {}), (info(stat.S_IFREG | 0o600, uid=1000), {}),
        (info(stat.S_IFREG | 0o644), {}), (info(stat.S_IFREG | 0o666), {'private': False}),
        (info(stat.S_IFDIR | 0o777), {'directory': True}),
        (info(stat.S_IFREG | 0o600), {'directory': True}),
    ):
        with pytest.raises(ValueError):
            require_owned(value, uid=0, **options)


@pytest.fixture
def owned_files(tmp_path, monkeypatch):
    if os.name != 'posix':
        pytest.skip('POSIX owner/mode/hardlink lifecycle runs in Linux CI')
    from orchestrator import service_forward_node_helper as helper
    roots = {key: str(tmp_path / key) for key in helper.ROOTS}
    for path in roots.values():
        os.mkdir(path, 0o700)
    monkeypatch.setattr(helper, 'ROOTS', roots)
    runtime, programs = descriptor()
    return helper.OwnedResources(runtime), runtime, programs


def test_owned_namespace_claim_and_book_are_idempotent_and_foreign_nonce_is_preserved(owned_files):
    from pathlib import Path
    owned, runtime, _ = owned_files
    owned.claim()
    owned.claim()
    owned.write_book([runtime['config']['listen_port']])
    book = Path(owned.paths['book'])
    first = book.stat().st_ino
    owned.write_book([runtime['config']['listen_port']])
    assert book.stat().st_ino == first
    assert owned.book_owned()
    # A legitimate different run can own the random-nonce filename; UUID alone
    # never authorizes deleting that unrelated inode after an uncertain operation.
    book.unlink()
    book.write_text('{"ports":[31000],"prefixes":[],"identifiers":[],"interfaces":[]}')
    book.chmod(0o600)
    before = book.read_bytes()
    assert not owned.book_owned()
    with pytest.raises(ValueError):
        owned.remove_book()
    assert book.read_bytes() == before


def test_foreign_certificate_and_symlink_never_claim_or_overwrite_a_directory(owned_files):
    from pathlib import Path
    owned, runtime, _ = owned_files
    certificate = Path(owned.paths['certificate'])
    certificate.write_text(json.dumps({'schema': 1, 'id': runtime['config']['id'],
        'owner': '0' * 64, 'nonce': runtime['nonce'], 'deployment_id': runtime['deployment_id']}))
    certificate.chmod(0o600)
    before = certificate.read_bytes()
    with pytest.raises(ValueError):
        owned.claim()
    assert certificate.read_bytes() == before
    assert not Path(owned.paths['directory']).exists()
    certificate.unlink()
    destination = certificate.parent / 'foreign-data'
    destination.mkdir(mode=0o700)
    Path(owned.paths['directory']).symlink_to(destination, target_is_directory=True)
    with pytest.raises(ValueError):
        owned.claim()
    assert destination.is_dir()


def test_owned_book_update_removes_only_its_own_verified_global_link(owned_files):
    from pathlib import Path
    owned, runtime, _ = owned_files
    owned.claim()
    port = runtime['config']['listen_port']
    owned.write_book([port])
    owned.write_book([port, port + 1])
    book = Path(owned.paths['book'])
    assert json.loads(book.read_text())['ports'] == [port, port + 1]
    assert owned.book_owned()
    owned.remove_book()
    assert not book.exists()


def test_private_checkpoint_uses_separate_fresh_keys_and_authenticated_roundtrip(owned_files):
    from pathlib import Path
    owned, runtime, programs = owned_files
    owned.claim()
    value = {'runtime': runtime, 'programs': programs}
    first = owned.checkpoint(value)
    second = owned.checkpoint(value)
    assert first != second
    assert owned.restore_checkpoint(first) == value
    assert owned.restore_checkpoint(second) == value
    assert Path(first['key']).parent == Path(owned.paths['key_directory'])
    assert Path(first['backup']).parent == Path(owned.paths['backups'])
    assert Path(first['key']).read_bytes() != Path(second['key']).read_bytes()
    assert runtime['config']['upstream']['password'].encode() not in Path(first['backup']).read_bytes()
    envelope = json.loads(Path(first['backup']).read_bytes())
    envelope['ciphertext'] = envelope['ciphertext'][::-1]
    Path(first['backup']).write_text(json.dumps(envelope))
    with pytest.raises(ValueError):
        owned.restore_checkpoint(first)


def test_shared_book_root_may_be_readable_but_new_code_is_dynamic_user_readable(owned_files):
    from pathlib import Path
    owned, _, _ = owned_files
    import orchestrator.service_forward_node_helper as helper
    Path(helper.ROOTS['books']).chmod(0o755)
    Path(helper.ROOTS['code']).rmdir()
    owned.claim()
    assert stat.S_IMODE(Path(helper.ROOTS['code']).stat().st_mode) == 0o755
    assert stat.S_IMODE(Path(owned.paths['code_directory']).stat().st_mode) == 0o755
    assert stat.S_IMODE(Path(owned.paths['directory']).stat().st_mode) == 0o700


class FakeSystemd:
    def __init__(self, owned):
        self.owned, self.pid, self.events = owned, 0, []
        self.dropins = ''

    def show(self, service):
        assert service == self.owned.runtime['service']
        return {'MainPID': str(self.pid), 'ActiveState': 'active' if self.pid else 'inactive',
                'FragmentPath': self.owned.paths['unit'] if os.path.exists(self.owned.paths['unit']) else '',
                'DropInPaths': self.dropins}

    def action(self, verb, service=None):
        self.events.append((verb, service))
        if service:
            assert service == self.owned.runtime['service']
        if verb == 'stop':
            self.pid = 0
        if verb == 'start':
            import time
            from pathlib import Path
            self.pid = 1356 + sum(verb == 'start' for verb, _ in self.events)
            path = Path(self.owned.paths['state'])
            path.parent.mkdir(mode=0o700, exist_ok=True)
            runtime = json.loads(Path(self.owned.paths['manifest']).read_bytes())
            path.write_text(json.dumps({'id': runtime['config']['id'], 'route_id': runtime['config']['route_id'],
                'revision': runtime['config']['revision'], 'config_sha256': runtime['config_sha256'],
                'worker_pid': self.pid, 'listening': True, 'updated_at': time.time(),
                'password': 'status-must-not-pass-this-through'}))
            path.chmod(0o600)


def test_owned_source_apply_observe_and_stop_never_touch_parent_and_preserve_rescues(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    observed = source.apply(programs)
    assert observed['observed'] and observed['runtime']['worker_pid'] == 1357
    assert 'password' not in observed['runtime']
    assert source.observe()['runtime']['config_sha256'] == runtime['config_sha256']
    starts = systemd.events.count(('start', runtime['service']))
    source.apply(programs)  # Lost controller reply: adopt instead of starting twice.
    assert systemd.events.count(('start', runtime['service'])) == starts
    checkpoint = owned.checkpoint({'runtime': runtime, 'programs': programs})
    source.stop()
    source.stop()
    assert not Path(owned.paths['book']).exists()
    assert not Path(owned.paths['unit']).exists()
    assert not Path(owned.paths['config']).exists()
    assert Path(checkpoint['backup']).exists() and Path(checkpoint['key']).exists()
    assert Path(owned.paths['certificate']).exists()  # Audit/recovery identity retained.
    assert all(service in (None, runtime['service']) for _, service in systemd.events)


def test_changed_unit_or_foreign_dropin_blocks_cleanup_before_any_stop(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    source.apply(programs)
    before = len(systemd.events)
    systemd.dropins = '/etc/systemd/system/foreign.conf'
    with pytest.raises(ValueError):
        source.stop()
    assert len(systemd.events) == before and systemd.pid == 1357
    systemd.dropins = ''
    unit = Path(owned.paths['unit'])
    unit.write_text('foreign unit retained')
    with pytest.raises(ValueError):
        source.stop()
    assert unit.read_text() == 'foreign unit retained' and systemd.pid == 1357


def test_source_rejects_stale_status_and_modified_runtime_program(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    source.apply(programs)
    state = Path(owned.paths['state'])
    row = json.loads(state.read_text())
    row['updated_at'] = 1
    state.write_text(json.dumps(row))
    assert not source.observe()['observed']
    program = Path(owned.paths['code_directory']) / 'relay.py'
    program.write_text('foreign program')
    with pytest.raises(ValueError):
        source.stop()
    assert systemd.pid == 1357


def test_foreign_autostart_link_is_preserved_before_source_claim(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    wants = Path(owned.paths['unit']).parent / 'multi-user.target.wants'
    wants.mkdir(mode=0o755)
    link = wants / (runtime['service'] + '.service')
    link.symlink_to('/etc/systemd/system/foreign.service')
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd)
    with pytest.raises(ValueError):
        source.apply(programs)
    assert os.readlink(link) == '/etc/systemd/system/foreign.service'
    assert not systemd.events


def test_lost_reply_after_certificate_only_can_be_inspected_and_resumed(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    owned.exclusive(owned.paths['certificate'], owned.encode(owned.certificate))
    assert not Path(owned.paths['directory']).exists()
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    assert source.observe() == {'observed': False}
    assert source.apply(programs)['observed']


def revision(runtime, **changes):
    value = copy.deepcopy(runtime)
    value['config'].update(revision=runtime['config']['revision'] + 1, **changes)
    value['config_sha256'] = fingerprint(value['config'])
    return value


def test_forward_edit_checkpoints_before_stop_and_only_changes_own_worker(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    original = source.apply(programs)
    candidate = revision(runtime, listen_port=runtime['config']['listen_port'] + 1)
    action = systemd.action
    def checked(verb, service=None):
        if verb == 'stop':
            assert list(Path(owned.paths['backups']).glob('*.json'))
            assert list(Path(owned.paths['key_directory']).glob('*.key'))
        return action(verb, service)
    systemd.action = checked
    result = source.update(candidate, programs)
    assert result['observed'] and result['runtime']['revision'] == 2
    assert result['runtime']['worker_pid'] != original['runtime']['worker_pid']
    updated = SourceForward(candidate, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    assert updated.observe()['observed']
    assert json.loads(Path(owned.paths['book']).read_bytes())['ports'] == [candidate['config']['listen_port']]
    updated.stop()


def test_failed_forward_edit_restores_verified_old_settings_and_listener(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    source.apply(programs)
    candidate = revision(runtime, target_port=runtime['config']['target_port'] + 1)
    action = systemd.action
    failed = []
    def fail_once(verb, service=None):
        if verb == 'start' and not failed:
            failed.append(True)
            raise ValueError('injected new worker failure')
        return action(verb, service)
    systemd.action = fail_once
    result = source.update(candidate, programs)
    assert result['rolled_back'] and result['runtime']['revision'] == 1
    assert source.observe()['observed']
    assert json.loads(Path(owned.paths['config']).read_bytes()) == runtime['config']
    source.stop()


def test_stop_during_edit_accepts_only_known_old_or_new_generation(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    source.apply(programs)
    candidate = revision(runtime, target_port=runtime['config']['target_port'] + 1)
    source.update(candidate, programs)
    source.select_known(candidate).stop()
    assert not Path(owned.paths['unit']).exists() and systemd.pid == 0


def test_stopped_partial_edit_can_resume_only_from_verified_private_checkpoint(owned_files):
    from pathlib import Path
    from orchestrator.service_forward_node_helper import SourceForward
    owned, runtime, programs = owned_files
    systemd = FakeSystemd(owned)
    source = SourceForward(runtime, systemd=systemd, pid_uid=lambda pid: os.geteuid())
    source.apply(programs)
    candidate = revision(runtime, target_port=runtime['config']['target_port'] + 1)
    checkpoint = owned.checkpoint({'runtime': runtime, 'programs': programs})
    owned.update_reference(candidate, checkpoint)
    owned.write_book([runtime['config']['listen_port'], candidate['config']['listen_port']])
    source.stop(keep_reservation=True)
    # API died while source was partially written, before the new worker existed.
    owned.exclusive(owned.paths['config'], owned.encode(candidate['config']))
    assert source.update(candidate, programs)['runtime']['revision'] == 2
    assert json.loads(Path(owned.paths['config']).read_bytes()) == candidate['config']
    source.select_known(candidate).stop()


@pytest.mark.skipif(os.name != 'posix', reason='resident POSIX file descriptor checks')
def test_parent_probe_binds_pid_config_and_existing_accounting_without_returning_secrets(tmp_path, monkeypatch):
    import time
    from orchestrator import service_forward_node_helper as helper
    monkeypatch.setattr(helper, 'PARENT_ROOT', str(tmp_path))
    route = 'a' * 32
    directory = tmp_path / route / 'gateway'
    directory.mkdir(parents=True)
    config = {'password': 'parent-secret-stays-resident', 'monthly': {'secret': 'credit-key'}}
    (directory / 'config.json').write_text(json.dumps(config))
    state = {'worker_pid': 42, 'updated_at': time.time(), 'active': 'member',
             'healthy': {'member': True}, 'traffic_control_version': 1, 'monthly_accounting_version': 1}
    (directory / 'state.json').write_text(json.dumps(state))
    parent = {'route_id': route, 'service': 'tpmesh-123456789-0-gateway',
              'config_sha256': fingerprint(config), 'monthly_required': True}
    systemd = SimpleNamespace(show=lambda name: {'MainPID': '42', 'ActiveState': 'active'})
    result = helper.probe_parent(parent, systemd=systemd)
    assert result == {'parent_pid': 42, 'parent_config_sha256': fingerprint(config)}
    assert 'secret' not in json.dumps(result)
    for change in ({'worker_pid': 43}, {'updated_at': 1}, {'traffic_control_version': 0},
                   {'monthly_accounting_version': 0}, {'healthy': {'member': False}}):
        (directory / 'state.json').write_text(json.dumps({**state, **change}))
        with pytest.raises(ValueError):
            helper.probe_parent(parent, systemd=systemd)
    (directory / 'state.json').write_text(json.dumps(state))
    (directory / 'config.json').write_text('{"password":"changed"}')
    with pytest.raises(ValueError):
        helper.probe_parent(parent, systemd=systemd)
