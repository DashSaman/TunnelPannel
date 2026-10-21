"""Dependency-free, typed source-forward ownership helper.

Input validation is side-effect free. Privileged actions are added separately;
untrusted request fields never select program names, unit names or root paths.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import secrets
import subprocess
import time
from pathlib import Path
from pathlib import PurePosixPath

PROGRAMS = frozenset({'relay.py', 'mesh_gateway.py', 'service_forward_protocol.py'})
ROOTS = {'data': '/etc/tunnelpannel-forwards', 'code': '/opt/tunnelpannel-forwards',
         'units': '/etc/systemd/system', 'books': '/var/lib/tunnelpannel-engine-reservations',
         'state': '/var/lib', 'keys': '/etc/tunnelpannel-forward-rescue-keys'}
PARENT_ROOT = '/var/lib/tunnelpannel/mesh'


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def hex_value(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def validate_metadata(runtime):
    if not isinstance(runtime, dict) or not isinstance(runtime.get('config'), dict):
        raise ValueError('invalid service metadata')
    required = {'config', 'config_sha256', 'owner', 'deployment_id', 'nonce', 'service',
                'directory', 'code_directory', 'state_path', 'program_sha256', 'unit_text', 'unit_sha256'}
    if required - runtime.keys() or runtime.keys() - required - {'helper_sha256'}:
        raise ValueError('unexpected private metadata fields')
    config = runtime['config']
    identity = config.get('id')
    if (not hex_value(identity, 32) or not hex_value(config.get('route_id'), 32)
            or type(config.get('schema')) is not int or config['schema'] != 1
            or type(config.get('revision')) is not int or not 1 <= config['revision'] <= 2**31 - 1
            or not hex_value(runtime.get('owner'), 64) or not hex_value(runtime.get('deployment_id'), 32)
            or type(runtime.get('nonce')) is not int or not 100000000 <= runtime['nonce'] <= 999999999):
        raise ValueError('invalid service ownership')
    expected = {'service': 'tpforward-' + identity,
                'directory': '/etc/tunnelpannel-forwards/' + identity,
                'code_directory': '/opt/tunnelpannel-forwards/' + identity,
                'state_path': '/var/lib/tunnelpannel-forward-' + identity + '/state.json'}
    if any(runtime.get(key) != value for key, value in expected.items()):
        raise ValueError('invalid service paths')
    try:
        if len(json.dumps(config)) > 65536 or runtime.get('config_sha256') != fingerprint(config):
            raise ValueError('service config identity mismatch')
    except (TypeError, OverflowError):
        raise ValueError('invalid service configuration') from None
    hashes = runtime.get('program_sha256')
    if not isinstance(hashes, dict) or set(hashes) != PROGRAMS or not all(hex_value(v, 64) for v in hashes.values()):
        raise ValueError('invalid service program identities')
    unit = runtime.get('unit_text')
    if (not isinstance(unit, str) or len(unit) > 20000 or '\x00' in unit
            or runtime.get('unit_sha256') != hashlib.sha256(unit.encode()).hexdigest()):
        raise ValueError('service unit identity mismatch')
    if 'helper_sha256' in runtime and not hex_value(runtime['helper_sha256'], 64):
        raise ValueError('invalid helper identity')
    return json.loads(json.dumps(runtime, allow_nan=False))


def validate_programs(runtime, programs):
    validate_metadata(runtime)
    if not isinstance(programs, dict) or set(programs) != PROGRAMS:
        raise ValueError('invalid service program set')
    decoded = {}
    for name, value in programs.items():
        if not isinstance(value, str) or len(value) > 700000:
            raise ValueError('invalid service program size')
        try:
            data = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError('invalid source program encoding') from None
        if len(data) > 500000 or hashlib.sha256(data).hexdigest() != runtime['program_sha256'][name]:
            raise ValueError('service program identity mismatch')
        try:
            compile(data, name, 'exec')
        except (SyntaxError, ValueError, UnicodeError):
            raise ValueError('invalid source program') from None
        decoded[name] = data
    return decoded


def ownership_paths(runtime):
    value = validate_metadata(runtime)
    identity = value['config']['id']
    directory = PurePosixPath(ROOTS['data']) / identity
    code = PurePosixPath(ROOTS['code']) / identity
    state = PurePosixPath(ROOTS['state']) / ('tunnelpannel-forward-' + identity)
    return {key: str(path) for key, path in {
        'certificate': PurePosixPath(ROOTS['data']) / ('.owner-' + identity + '.json'),
        'directory': directory, 'config': directory / 'config.json',
        'manifest': directory / 'manifest.json', 'code_directory': code,
        'unit': PurePosixPath(ROOTS['units']) / (value['service'] + '.service'),
        'autostart': PurePosixPath(ROOTS['units']) / 'multi-user.target.wants' / (value['service'] + '.service'),
        'book': PurePosixPath(ROOTS['books']) / ('tp-' + str(value['nonce']) + '-0.json'),
        'book_directory': PurePosixPath(ROOTS['books']) / ('.tpforward-' + identity),
        'key_directory': PurePosixPath(ROOTS['keys']) / identity,
        'state_directory': state, 'state': state / 'state.json',
        'backups': directory / 'rescues',
    }.items()}


def require_owned(info, *, directory=False, private=True, uid=None):
    expected = getattr(os, 'geteuid', lambda: 0)() if uid is None else uid
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (info.st_uid != expected or not kind(info.st_mode)
            or info.st_mode & (0o077 if private else 0o022)
            or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)):
        raise ValueError('unsafe service artifact owner, kind or permissions')


class OwnedResources:
    """Root-private namespace certificate and inode-proven shared reservation.

    A matching controller ledger is intent, not proof of remote file ownership.
    The shared book is removed only while linked to a verified private stage.
    Callers hold both host leases for every mutating operation.
    """
    def __init__(self, runtime):
        self.runtime = validate_metadata(runtime)
        self.paths = ownership_paths(runtime)
        self.certificate = {'schema': 1, 'id': runtime['config']['id'],
                            **{key: runtime[key] for key in ('owner', 'nonce', 'deployment_id')}}

    @staticmethod
    def read(path, *, private=True, limit=1048576):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            require_owned(info, private=private)
            if info.st_size > limit:
                raise ValueError('service artifact exceeds limit')
            result = b''
            while len(result) <= limit:
                chunk = os.read(descriptor, min(65536, limit + 1 - len(result)))
                if not chunk:
                    return result
                result += chunk
            raise ValueError('service artifact exceeds limit')
        finally:
            os.close(descriptor)

    @staticmethod
    def directory(path, *, private=True):
        try:
            os.mkdir(path, 0o700 if private else 0o755)
        except FileExistsError:
            require_owned(os.lstat(path), directory=True, private=private)
            return  # Never widen permissions on an existing/foreign directory.
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require_owned(os.fstat(descriptor), directory=True, private=private)
            os.fchmod(descriptor, 0o700 if private else 0o755)
        finally:
            os.close(descriptor)
        require_owned(os.lstat(path), directory=True, private=private)

    @staticmethod
    def exclusive(path, data, mode=0o600):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)  # Explicit mode despite caller umask.
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            # Leave partial owned artifacts for explicit inspection, never replace
            # an uncertain artifact with a fresh claim after a lost write reply.
            raise

    @staticmethod
    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

    def verify(self):
        if json.loads(self.read(self.paths['certificate'], limit=2048)) != self.certificate:
            raise ValueError('foreign service namespace certificate')

    def claim(self):
        # State root is the existing public /var/lib; all dedicated bases are private.
        for name in ('data', 'code', 'books', 'keys'):
            self.directory(ROOTS[name], private=name not in {'code', 'books'})
        certificate = self.paths['certificate']
        if not os.path.lexists(certificate):
            if os.path.lexists(self.paths['book']):
                raise ValueError('foreign reservation nonce already exists')
            for key in ('directory', 'code_directory', 'unit', 'autostart', 'book_directory',
                        'key_directory', 'state_directory'):
                if os.path.lexists(self.paths[key]):
                    raise ValueError('unmarked service namespace already exists')
            try:
                self.exclusive(certificate, self.encode(self.certificate))
            except FileExistsError:
                pass
        self.verify()
        for key in ('directory', 'code_directory', 'book_directory', 'key_directory'):
            self.directory(self.paths[key], private=key != 'code_directory')

    def _stages(self):
        self.verify()
        root = self.paths['book_directory']
        require_owned(os.lstat(root), directory=True)
        result = []
        for entry in os.scandir(root):
            if not re.fullmatch(r'book-[0-9a-f]{64}\.json', entry.name):
                raise ValueError('unexpected private reservation artifact')
            data = self.read(entry.path, limit=8192)
            if hashlib.sha256(data).hexdigest() != entry.name[5:-5]:
                raise ValueError('changed private reservation artifact')
            value = json.loads(data)
            if (set(value) != {'ports', 'prefixes', 'identifiers', 'interfaces'}
                    or any(value[key] != [] for key in ('prefixes', 'identifiers', 'interfaces'))
                    or not isinstance(value['ports'], list)
                    or not all(type(port) is int and 1024 <= port <= 65535 for port in value['ports'])):
                raise ValueError('invalid private reservation artifact')
            result.append((os.lstat(entry.path), data))
        return result

    def book_owned(self):
        stages = self._stages()
        try:
            info = os.lstat(self.paths['book'])
        except FileNotFoundError:
            return False
        require_owned(info)
        data = self.read(self.paths['book'], limit=8192)
        return any((info.st_dev, info.st_ino) == (stage.st_dev, stage.st_ino) and data == expected
                   for stage, expected in stages)

    def write_book(self, ports):
        self.verify()
        if (not isinstance(ports, list) or not ports or len(ports) > 2
                or not all(type(port) is int and 1024 <= port <= 65535 for port in ports)):
            raise ValueError('invalid owned reservation ports')
        data = self.encode({'ports': sorted(set(ports)), 'prefixes': [], 'identifiers': [], 'interfaces': []})
        stage = str(Path(self.paths['book_directory']) / ('book-' + hashlib.sha256(data).hexdigest() + '.json'))
        try:
            self.exclusive(stage, data)
        except FileExistsError:
            if self.read(stage, limit=8192) != data:
                raise ValueError('changed owned reservation stage') from None
        book = self.paths['book']
        if not os.path.lexists(book):
            os.link(stage, book, follow_symlinks=False)  # O_EXCL semantics: foreign nonce is preserved.
            return
        if not self.book_owned():
            raise ValueError('foreign service reservation collision')
        if self.read(book, limit=8192) == data:
            return
        temporary = str(Path(book).parent / ('.forward-' + secrets.token_hex(16)))
        try:
            os.link(stage, temporary, follow_symlinks=False)
            # Host lease excludes other cooperative writers; verify immediately
            # before replacement, rather than trusting the earlier observation.
            if not self.book_owned():
                raise ValueError('service reservation changed during update')
            os.replace(temporary, book)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)

    def remove_book(self):
        self.verify()
        if not os.path.lexists(self.paths['book']):
            return
        if not self.book_owned():
            raise ValueError('refusing foreign service reservation cleanup')
        os.unlink(self.paths['book'])

    @staticmethod
    def _crypt(data, key_path, *, decrypt=False):
        args = ['/usr/bin/openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000',
                '-pass', 'file:' + key_path]
        if decrypt:
            args.append('-d')
        result = subprocess.run(args, input=data, capture_output=True, timeout=20)
        if result.returncode:
            raise ValueError('private service checkpoint encryption failed')
        return result.stdout

    def checkpoint(self, value):
        self.verify()
        self.directory(self.paths['backups'])
        self.directory(self.paths['key_directory'])
        plaintext = self.encode(value)
        if len(plaintext) > 4000000:
            raise ValueError('private service checkpoint exceeds limit')
        identity = secrets.token_hex(16)
        key_path = str(Path(self.paths['key_directory']) / (identity + '.key'))
        backup_path = str(Path(self.paths['backups']) / (identity + '.json'))
        key = secrets.token_hex(32).encode()
        self.exclusive(key_path, key)
        ciphertext = self._crypt(plaintext, key_path)
        envelope = {'schema': 1, 'ciphertext': base64.b64encode(ciphertext).decode(),
                    'plaintext_sha256': hashlib.sha256(plaintext).hexdigest(),
                    'mac': hmac.new(key, ciphertext, hashlib.sha256).hexdigest()}
        self.exclusive(backup_path, self.encode(envelope))
        reference = {'backup': backup_path, 'key': key_path}
        if self.restore_checkpoint(reference) != value:
            raise ValueError('private service checkpoint verification failed')
        return reference

    def restore_checkpoint(self, reference):
        self.verify()
        if not isinstance(reference, dict) or set(reference) != {'backup', 'key'}:
            raise ValueError('invalid private service checkpoint reference')
        backup, key_path = Path(reference['backup']), Path(reference['key'])
        if (backup.parent != Path(self.paths['backups']) or key_path.parent != Path(self.paths['key_directory'])
                or not re.fullmatch(r'[0-9a-f]{32}\.json', backup.name)
                or key_path.name != backup.stem + '.key'):
            raise ValueError('invalid private service checkpoint paths')
        for directory in (backup.parent, key_path.parent):
            require_owned(os.lstat(directory), directory=True)
        key = self.read(str(key_path), limit=64)
        if not re.fullmatch(b'[0-9a-f]{64}', key):
            raise ValueError('invalid private service checkpoint key')
        envelope = json.loads(self.read(str(backup), limit=6000000))
        try:
            if set(envelope) != {'schema', 'ciphertext', 'plaintext_sha256', 'mac'} or envelope['schema'] != 1:
                raise ValueError('invalid checkpoint envelope')
            ciphertext = base64.b64decode(envelope['ciphertext'], validate=True)
            if not hmac.compare_digest(envelope['mac'], hmac.new(key, ciphertext, hashlib.sha256).hexdigest()):
                raise ValueError('checkpoint authentication failed')
            plaintext = self._crypt(ciphertext, str(key_path), decrypt=True)
            if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), envelope['plaintext_sha256']):
                raise ValueError('checkpoint plaintext identity changed')
            return json.loads(plaintext)
        except (KeyError, TypeError, binascii.Error):
            raise ValueError('invalid private service checkpoint') from None

    def update_reference(self, candidate, reference=None):
        self.verify()
        target = str(Path(self.paths['directory']) / ('.update-' + fingerprint(candidate) + '.json'))
        expected = {'old_fingerprint': fingerprint(self.runtime), 'new_fingerprint': fingerprint(candidate)}
        previous = None
        if os.path.lexists(target):
            previous = self.read(target, limit=4096)
            record = json.loads(previous)
            if (not isinstance(record, dict) or set(record) != {*expected, 'checkpoint'}
                    or any(record.get(key) != value for key, value in expected.items())
                    or self.restore_checkpoint(record['checkpoint']).get('runtime') != self.runtime):
                raise ValueError('invalid private forward update checkpoint')
            if reference is None:
                return record['checkpoint']
        if reference is None:
            raise ValueError('private forward update checkpoint unavailable')
        data = self.encode({**expected, 'checkpoint': reference})
        if previous is None:
            self.exclusive(target, data)
        else:
            temporary = str(Path(target).parent / ('.write-' + secrets.token_hex(16)))
            self.exclusive(temporary, data)
            try:
                if self.read(target, limit=4096) != previous:
                    raise ValueError('private forward update changed')
                os.replace(temporary, target)
            finally:
                if os.path.lexists(temporary):
                    os.unlink(temporary)
        return reference


class Systemd:
    def show(self, service):
        result = subprocess.run(['systemctl', 'show', service + '.service',
            '--property=MainPID,ActiveState,FragmentPath,DropInPaths'], capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ValueError('service unit inspection unavailable')
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    def action(self, verb, service=None):
        args = ['systemctl', verb]
        if verb == 'clean':
            args.append('--what=state')
        if service:
            args.append(service + '.service')
        result = subprocess.run(args, capture_output=True, timeout=20)
        if result.returncode:
            raise ValueError('owned service unit operation failed')


def read_resident_json(path, limit=1048576):
    # Existing parent files may be owned by the API service account after an
    # ordinary upgrade. Observe bounded regular bytes; do not change their modes.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('invalid resident service artifact')
        data = os.read(descriptor, limit + 1)
        if len(data) > limit:
            raise ValueError('resident service artifact exceeds limit')
        return json.loads(data)
    finally:
        os.close(descriptor)


def probe_parent(parent, *, systemd=None):
    if (not isinstance(parent, dict) or set(parent) != {'route_id', 'service', 'config_sha256', 'monthly_required'}
            or not hex_value(parent.get('route_id'), 32) or not hex_value(parent.get('config_sha256'), 64)
            or not re.fullmatch(r'tpmesh-[1-9][0-9]{8}-0-gateway', str(parent.get('service')))
            or type(parent.get('monthly_required')) is not bool):
        raise ValueError('invalid parent inspection identity')
    directory = Path(PARENT_ROOT) / parent['route_id'] / 'gateway'
    config = read_resident_json(str(directory / 'config.json'))
    if fingerprint(config) != parent['config_sha256']:
        raise ValueError('parent configuration changed')
    status = (systemd or Systemd()).show(parent['service'])
    state = read_resident_json(str(directory / 'state.json'))
    pid = state.get('worker_pid')
    if (type(pid) is not int or pid <= 0 or status.get('MainPID') != str(pid)
            or status.get('ActiveState') != 'active' or type(state.get('updated_at')) not in (int, float)
            or not 0 <= time.time() - state['updated_at'] < 30 or not state.get('active')
            or state.get('healthy', {}).get(state['active']) is not True
            or type(state.get('traffic_control_version')) is not int or state['traffic_control_version'] != 1
            or parent['monthly_required'] and (type(state.get('monthly_accounting_version')) is not int
                                               or state['monthly_accounting_version'] != 1)):
        raise ValueError('parent worker is stale, unhealthy or requires accounting migration')
    return {'parent_pid': pid, 'parent_config_sha256': parent['config_sha256']}


def resident_controls():
    path = '/etc/tunnelpannel/tunnelpannel.env'
    try:
        # install.sh intentionally uses root:tunnelpannel 0640. Observe only
        # root-owned, non-writable regular bytes; return the port, never secrets.
        data = OwnedResources.read(path, private=False, limit=65536).decode()
    except FileNotFoundError:
        return []
    ports = []
    for line in data.splitlines():
        key, separator, value = line.partition('=')
        if separator and key.strip() == 'TUNNELPANNEL_PORT':
            value = value.strip().strip('\"\'')
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise ValueError('invalid resident control port')
            ports.append(int(value))
    return sorted(set(ports))


def owned_socket(runtime, observed):
    if observed.get('observed') is not True:
        return None
    port, pid = runtime['config']['listen_port'], observed['runtime']['worker_pid']
    result = subprocess.run(['ss', '-tlpnH'], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError('socket ownership inspection unavailable')
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split()
        # ss -t (without -u) omits the Netid column.
        if len(parts) < 4:
            raise ValueError('invalid socket ownership inspection')
        if parts[3].rpartition(':')[2] == str(port):
            rows.append(line)
    if len(rows) != 1 or set(re.findall(r'pid=([0-9]+)', rows[0])) != {str(pid)}:
        raise ValueError('listener is not exclusively owned by the service worker')
    return {'verified': True, 'port': port, 'pid': pid}


def dispatch(request):
    if os.geteuid() != 0 or not isinstance(request, dict):
        raise ValueError('privileged typed service operation required')
    action = request.get('action')
    fields = {
        'parent': {'action', 'parent'}, 'controls': {'action'},
        'observe': {'action', 'runtime'}, 'socket': {'action', 'runtime'},
        'apply': {'action', 'runtime', 'programs', 'parent', 'inspection'},
        'update': {'action', 'runtime', 'candidate', 'programs', 'parent', 'inspection'},
        'stop': {'action', 'runtime'},
    }
    optional = {'alternative'} if action in {'socket', 'stop'} else set()
    if action not in fields or fields[action] - set(request) or set(request) - fields[action] - optional:
        raise ValueError('unexpected service operation fields')
    if action == 'parent':
        return probe_parent(request['parent'])
    if action == 'controls':
        return resident_controls()
    source = SourceForward(request['runtime'])
    if 'alternative' in request:
        source = source.select_known(request['alternative'])
    if action == 'observe':
        return source.observe()
    if action == 'socket':
        return owned_socket(source.runtime, source.observe())
    if action in {'apply', 'update'}:
        if probe_parent(request['parent']) != request['inspection']:
            raise ValueError('parent changed before source activation')
        if action == 'update':
            return source.update(request['candidate'], request['programs'])
        return source.apply(request['programs'])
    source.stop()
    return {'stopped': True}


class SourceForward:
    """Operate one certificate-proven unit; never issue commands for its parent."""
    def __init__(self, runtime, *, systemd=None, pid_uid=None):
        self.runtime = validate_metadata(runtime)
        self.owned = OwnedResources(runtime)
        self.paths = self.owned.paths
        self.systemd = systemd or Systemd()
        self.pid_uid = pid_uid or (lambda pid: os.stat('/proc/' + str(pid)).st_uid)

    def _expected(self):
        paths, runtime = self.paths, self.runtime
        values = {paths['config']: (runtime['config_sha256'], True),
                  paths['manifest']: (fingerprint(runtime), True),
                  paths['unit']: (runtime['unit_sha256'], False)}
        values.update({str(Path(paths['code_directory']) / name): (sha, False)
                       for name, sha in runtime['program_sha256'].items()})
        return values

    def _verify_files(self, *, required):
        self.owned.verify()
        link = self.paths['autostart']
        if os.path.lexists(link):
            info = os.lstat(link)
            require_owned(os.lstat(str(Path(link).parent)), directory=True, private=False)
            if (not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
                    or os.path.normpath(os.path.join(str(Path(link).parent), os.readlink(link))) != self.paths['unit']):
                raise ValueError('foreign service autostart link')
        for key in ('directory', 'code_directory', 'book_directory', 'key_directory'):
            if not os.path.lexists(self.paths[key]) and not required:
                continue
            require_owned(os.lstat(self.paths[key]), directory=True, private=key != 'code_directory')
        for path, (expected, private) in self._expected().items():
            if not os.path.lexists(path) and not required:
                continue
            if hashlib.sha256(self.owned.read(path, private=private)).hexdigest() != expected:
                raise ValueError('service artifact identity changed')

    def _status(self):
        status = self.systemd.show(self.runtime['service'])
        if (status.get('DropInPaths') or status.get('FragmentPath') not in ('', self.paths['unit'])
                or not str(status.get('MainPID', '')).isdigit()):
            raise ValueError('foreign unit definition or override')
        return status

    def _absent(self):
        if os.path.lexists(self.paths['certificate']):
            return False
        for key in ('directory', 'code_directory', 'unit', 'autostart', 'book_directory', 'key_directory', 'state_directory'):
            if os.path.lexists(self.paths[key]):
                raise ValueError('unmarked service artifact')
        status = self._status()
        if status.get('FragmentPath') or int(status['MainPID']):
            raise ValueError('unmarked live service unit')
        return True

    def observe(self):
        if self._absent():
            return {'observed': False}
        self._verify_files(required=False)
        status = self._status()
        pid = int(status['MainPID'])
        if status.get('ActiveState') != 'active' or pid <= 0:
            return {'observed': False}
        self._verify_files(required=True)
        if not self.owned.book_owned():
            return {'observed': False}
        try:
            descriptor = os.open(self.paths['state'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require_owned(os.fstat(descriptor), uid=self.pid_uid(pid))
                data = os.read(descriptor, 65537)
            finally:
                os.close(descriptor)
            if len(data) > 65536:
                raise ValueError('oversized service state')
            state = json.loads(data)
            config = self.runtime['config']
            valid = (state.get('id') == config['id'] and state.get('route_id') == config['route_id']
                and state.get('revision') == config['revision'] and type(state.get('worker_pid')) is int
                and state['worker_pid'] == pid and state.get('listening') is True
                and state.get('config_sha256') == self.runtime['config_sha256']
                and type(state.get('updated_at')) in (int, float) and 0 <= time.time() - state['updated_at'] < 30)
        except (OSError, ValueError, TypeError):
            return {'observed': False}
        if not valid:
            return {'observed': False}
        return {'observed': True, 'reservation_ports': json.loads(self.owned.read(self.paths['book'], limit=8192))['ports'],
                'runtime': {key: state[key] for key in
            ('id', 'route_id', 'revision', 'config_sha256', 'worker_pid', 'listening', 'updated_at')}}

    def apply(self, programs):
        decoded = validate_programs(self.runtime, programs)
        if not self._absent():
            self._verify_files(required=False)
            status = self._status()
            if int(status['MainPID']):
                observed = self.observe()
                if observed['observed']:
                    return observed
                raise ValueError('existing worker needs explicit recovery inspection')
        self.owned.claim()
        self._verify_files(required=False)
        self._status()
        files = {self.paths['config']: (self.owned.encode(self.runtime['config']), 0o600),
                 self.paths['manifest']: (self.owned.encode(self.runtime), 0o600),
                 self.paths['unit']: (self.runtime['unit_text'].encode(), 0o644)}
        files.update({str(Path(self.paths['code_directory']) / name): (data, 0o644)
                      for name, data in decoded.items()})
        for path, (data, mode) in files.items():
            try:
                self.owned.exclusive(path, data, mode)
            except FileExistsError:
                if self.owned.read(path, private=mode == 0o600) != data:
                    raise ValueError('refusing changed owned service artifact') from None
        self.owned.write_book([self.runtime['config']['listen_port']])
        for verb in ('daemon-reload', 'enable', 'start'):
            self.systemd.action(verb, None if verb == 'daemon-reload' else self.runtime['service'])
        deadline = time.monotonic() + 12
        while True:
            observed = self.observe()
            if observed['observed']:
                return observed
            if time.monotonic() >= deadline:
                raise ValueError('owned service worker did not become observable')
            time.sleep(.1)

    def _successor(self, candidate):
        candidate = validate_metadata(candidate)
        if (any(candidate[key] != self.runtime[key] for key in ('owner', 'deployment_id', 'nonce', 'service',
                    'directory', 'code_directory', 'state_path'))
                or candidate['config']['id'] != self.runtime['config']['id']
                or candidate['config']['route_id'] != self.runtime['config']['route_id']
                or candidate['config']['revision'] != self.runtime['config']['revision'] + 1):
            raise ValueError('forward edit changed ownership, parent or revision')
        return SourceForward(candidate, systemd=self.systemd, pid_uid=self.pid_uid)

    def select_known(self, candidate):
        updated = self._successor(candidate)
        for source in (self, updated):
            try:
                if not source._absent():
                    source._verify_files(required=False)
                source._status()
                return source
            except (ValueError, OSError):
                continue
        raise ValueError('service artifacts match neither known generation')

    def update(self, candidate, programs):
        updated = self._successor(candidate)
        candidate = updated.runtime
        validate_programs(candidate, programs)
        try:
            observed = updated.observe()
        except (ValueError, OSError):
            observed = {'observed': False}
        if observed['observed']:
            self.owned.write_book([candidate['config']['listen_port']])
            return updated.observe()  # Lost apply reply: exactly the same generation.
        selected = self.select_known(candidate)
        try:
            self._verify_files(required=True)
            complete_old = True
        except (ValueError, OSError):
            complete_old = False
        if complete_old:
            old_programs = {name: base64.b64encode(self.owned.read(
                str(Path(self.paths['code_directory']) / name), private=False)).decode() for name in PROGRAMS}
            validate_programs(self.runtime, old_programs)
            checkpoint = self.owned.checkpoint({'runtime': self.runtime, 'programs': old_programs})
            self.owned.update_reference(candidate, checkpoint)  # Durable BEFORE first stop.
        else:
            if int(selected._status()['MainPID']):
                raise ValueError('partially defined live forward requires owned stop first')
            checkpoint = self.owned.update_reference(candidate)
            saved = self.owned.restore_checkpoint(checkpoint)
            validate_programs(self.runtime, saved['programs'])
            self.owned.checkpoint({'recovery_of': fingerprint(candidate), 'known_files': {
                str(Path(path).name): base64.b64encode(self.owned.read(path, private=private)).decode()
                for path, (_, private) in selected._expected().items() if os.path.lexists(path)}})
        self.owned.write_book([self.runtime['config']['listen_port'], candidate['config']['listen_port']])
        selected.stop(keep_reservation=True)
        try:
            return updated.apply(programs)
        except Exception:
            # An unknown/tampered new artifact blocks rollback too. Never erase it
            # merely because an earlier controller operation intended to own it.
            saved = self.owned.restore_checkpoint(checkpoint)
            if saved['runtime'] != self.runtime:
                raise ValueError('old forward checkpoint identity changed') from None
            validate_programs(self.runtime, saved['programs'])
            updated.stop(keep_reservation=True)
            result = self.apply(saved['programs'])
            return {**result, 'rolled_back': True}

    def stop(self, *, keep_reservation=False):
        if self._absent():
            return
        self._verify_files(required=False)
        status = self._status()
        unit_present = os.path.lexists(self.paths['unit'])
        if int(status['MainPID']) and not unit_present:
            raise ValueError('unverified live service unit')
        # Prove reservation ownership BEFORE any worker mutation, including cleanup.
        if os.path.lexists(self.paths['book']) and not self.owned.book_owned():
            raise ValueError('foreign service reservation collision')
        if unit_present:
            for verb in ('stop', 'disable', 'clean'):
                self.systemd.action(verb, self.runtime['service'])
            if int(self._status()['MainPID']):
                raise ValueError('owned service worker remains active')
        if not keep_reservation:
            self.owned.remove_book()
        self._verify_files(required=False)
        if os.path.lexists(self.paths['autostart']):
            os.unlink(self.paths['autostart'])
        for path in self._expected():
            if os.path.lexists(path):
                os.unlink(path)
        if unit_present:
            self.systemd.action('daemon-reload')
