"""Fresh node coexistence policy and dedicated source-forward unit contract."""
from __future__ import annotations

import re
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path

from orchestrator.host_lease import HostLease
from orchestrator.remote_nodes import NodeRemote
from orchestrator.service_forward_node_helper import fingerprint, validate_metadata, validate_programs

from orchestrator.resources import NEVER_PORTS
from orchestrator.service_forward_protocol import canonical_address, literal_address, normalize_cidrs, validate_exposure


class ForwardBlocked(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def node_addresses(report):
    if (not isinstance(report, dict) or report.get('schema') != 1 or report.get('complete') is not True
            or report.get('errors') != [] or not isinstance(report.get('networks'), dict)
            or not isinstance(report.get('listeners'), list)):
        raise ForwardBlocked('inventory_incomplete')
    result = {'127.0.0.1', '::1'}
    try:
        for family in ('-4', '-6'):
            rows = report['networks'][family + '_addresses']
            if not isinstance(rows, list):
                raise ValueError('invalid address collection')
            for row in rows:
                for address in row.get('addr_info', []):
                    if address.get('local'):
                        result.add(str(literal_address(address['local'])))
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ForwardBlocked('inventory_incomplete') from None
    return result


def validate_source(report, spec, *, owned=None):
    addresses = node_addresses(report)
    try:
        bind = literal_address(canonical_address(spec['bind_host']))
        cidrs = normalize_cidrs(spec['source_cidrs'])
        validate_exposure(str(bind), spec['allow_public'], cidrs)
        port = spec['bind_port']
        if type(port) is not int or not 1024 <= port <= 65535 or port in NEVER_PORTS:
            raise ValueError('invalid service port')
        if not bind.is_unspecified and str(bind) not in addresses:
            raise ForwardBlocked('bind_address_not_owned')
        if any(low <= port <= high for low, high in report.get('reserved_ranges', {}).get('TCP', [])):
            raise ForwardBlocked('port_reserved')
        busy = [row for row in report['listeners'] if row['proto'] == 'TCP' and row['port'] == port]
    except ForwardBlocked:
        raise
    except (KeyError, TypeError, ValueError):
        raise ForwardBlocked('inventory_or_bind_invalid') from None
    if busy:
        proof = owned or {}
        if not (proof.get('verified') is True and proof.get('port') == port
                and type(proof.get('pid')) is int and proof['pid'] > 0
                and len(busy) == 1 and busy[0].get('source') == 'socket'):
            raise ForwardBlocked('port_in_use')


def target_listener(row, target, port):
    if row.get('proto') != 'TCP' or row.get('port') != port:
        return False
    address = str(row.get('addr', '')).strip('[]')
    if address in {'', '*'}:
        return True  # Configured wildcard; application health is still unasserted.
    try:
        value = literal_address(address)
        return value == target or value.is_unspecified and value.version == target.version
    except ValueError:
        raise ForwardBlocked('inventory_incomplete') from None


def validate_target(report, spec, *, forbidden_ports=()):
    addresses = node_addresses(report)
    try:
        target = literal_address(canonical_address(spec['target_host'], target=True))
        port = spec['target_port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('invalid target port')
        if str(target) not in addresses:
            raise ForwardBlocked('target_address_not_owned')
        if port in set(forbidden_ports) | {22, 2375, 2376, 3306, 5432, 6379, 6443, 11211, 27017}:
            raise ForwardBlocked('target_control_port')
        rows = [row for row in report['listeners'] if target_listener(row, target, port)]
        if not rows:
            raise ForwardBlocked('target_not_listening')
        if any(row.get('proc') in {'sshd', 'postgres', 'redis-server', 'mysqld', 'dockerd', 'uvicorn'} for row in rows):
            raise ForwardBlocked('target_control_port')
    except ForwardBlocked:
        raise
    except (KeyError, TypeError, ValueError):
        raise ForwardBlocked('inventory_or_target_invalid') from None


def unit_text(runtime):
    identity = runtime['config']['id']
    if not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{32}', identity):
        raise ForwardBlocked('invalid_owner_identity')
    expected = {'service': 'tpforward-' + identity,
                'directory': '/etc/tunnelpannel-forwards/' + identity,
                'code_directory': '/opt/tunnelpannel-forwards/' + identity,
                'state_path': '/var/lib/tunnelpannel-forward-' + identity + '/state.json'}
    if any(runtime.get(key) != value for key, value in expected.items()):
        raise ForwardBlocked('invalid_owner_paths')
    return f'''[Unit]
Description=TehNet managed TCP service {identity}
After=network-online.target

[Service]
Type=simple
DynamicUser=yes
LoadCredential=forward.json:{runtime['directory']}/config.json
ExecStart=/usr/bin/python3 {runtime['code_directory']}/relay.py --config %d/forward.json --state {runtime['state_path']}
StateDirectory=tunnelpannel-forward-{identity}
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
KillMode=control-group
TimeoutStopSec=5
Restart=on-failure
RestartSec=2
MemoryMax=256M
TasksMax=32
LimitNOFILE=65536
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''


def program_bytes():
    directory = Path(__file__).parent
    return {name: (directory / source).read_text(encoding='utf-8').encode() for name, source in (
        ('relay.py', 'service_forward_runtime.py'), ('mesh_gateway.py', 'mesh_gateway.py'),
        ('service_forward_protocol.py', 'service_forward_protocol.py'))}


def prepare_runtime(runtime):
    value = dict(runtime)
    value['program_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in program_bytes().items()}
    value['unit_text'] = unit_text(value)
    value['unit_sha256'] = hashlib.sha256(value['unit_text'].encode()).hexdigest()
    return validate_metadata(value)


class ForwardNodeDriver:
    def __init__(self, *, remote_factory=None, scanner=None):
        from orchestrator.host_inventory import scan
        self.remote_factory, self.scanner = remote_factory or NodeRemote, scanner or scan

    @contextmanager
    def _remotes(self, context, *, destination=True):
        endpoints = [context['source'], context['destination']]
        leases = sorted([HostLease(row) for row in endpoints], key=lambda row: row.key)
        if leases[0].key == leases[1].key:
            raise ForwardBlocked('same_physical_host')
        held, remotes = [], {}
        try:
            for lease in leases:
                if not lease.acquire(5):
                    raise ForwardBlocked('host_controller_busy')
                held.append(lease)
            for endpoint in endpoints if destination else endpoints[:1]:
                remote = self.remote_factory(endpoint, context['access'][endpoint['id']])
                remotes[endpoint['id']] = remote
                remote.connect()
            yield remotes
        finally:
            for remote in remotes.values():
                remote.close()
            for lease in reversed(held):
                lease.release()

    def _call(self, remote, request):
        # Dedicated test seam; production sends the reviewed CURRENT helper and
        # private input through SSH stdin, never argv or an old server-side copy.
        if hasattr(remote, 'forward_call'):
            return remote.forward_call(request)
        helper = Path(__file__).with_name('service_forward_node_helper.py').read_text(encoding='utf-8')
        compile(helper, 'service_forward_node_helper.py', 'exec')
        sha = hashlib.sha256(helper.encode()).hexdigest()
        source = base64.b64encode(helper.encode()).decode()
        payload = base64.b64encode(json.dumps(request, allow_nan=False).encode()).decode()
        script = f'''import base64, hashlib, json
source = base64.b64decode({source!r})
assert hashlib.sha256(source).hexdigest() == {sha!r}
namespace = {{'__name__': '__tp_forward_helper__'}}
try:
    exec(compile(source, 'service_forward_node_helper.py', 'exec'), namespace)
    result = namespace['dispatch'](json.loads(base64.b64decode({payload!r})))
    print(json.dumps({{'ok': True, 'helper_sha256': {sha!r}, 'result': result}}, allow_nan=False))
except Exception:
    print(json.dumps({{'ok': False, 'helper_sha256': {sha!r}}}))
'''
        command = 'python3 -' if remote.endpoint['ssh_username'] == 'root' else 'sudo -n python3 -'
        stdin, stdout, stderr = remote.client.exec_command(command, timeout=90)
        try:
            stdin.write(script)
            stdin.flush()
            stdin.channel.shutdown_write()
            raw = stdout.read(1048577)
            stderr.read(65537)  # Never return raw privileged diagnostics/configuration.
            status = stdout.channel.recv_exit_status()
            if status or len(raw) > 1048576:
                raise ValueError('invalid helper response')
            response = json.loads(raw)
            if (response.get('ok') is not True or response.get('helper_sha256') != sha
                    or set(response) != {'ok', 'helper_sha256', 'result'}):
                raise ValueError('unverified helper response')
            return response['result']
        except Exception:
            raise ForwardBlocked('owned_source_operation_unavailable') from None
        finally:
            stdin.close()
            stdout.close()
            stderr.close()

    @staticmethod
    def _parent(context):
        runtime = context['parent_runtime']
        expected = '/var/lib/tunnelpannel/mesh/' + context['route_id'] + '/gateway'
        if runtime.get('directory', expected) != expected:
            raise ForwardBlocked('parent_namespace_changed')
        return {'route_id': context['route_id'], 'service': runtime['service'],
                'config_sha256': fingerprint(runtime['config']),
                'monthly_required': context.get('requires_monthly', bool(runtime['config'].get('monthly')))}

    @staticmethod
    def _spec(runtime):
        config = runtime['config']
        return {'bind_host': config['listen_host'], 'bind_port': config['listen_port'],
                **{key: config[key] for key in ('target_host', 'target_port', 'source_cidrs', 'allow_public')}}

    def _inspect_locked(self, context, spec, remotes, owned=None):
        source = remotes[context['source']['id']]
        destination = remotes[context['destination']['id']]
        parent = self._call(source, {'action': 'parent', 'parent': self._parent(context)})
        proof = None
        if owned:
            request = {'action': 'socket', 'runtime': owned[0] if isinstance(owned, list) else owned}
            if isinstance(owned, list):
                if len(owned) != 2:
                    raise ForwardBlocked('invalid_owned_generations')
                request['alternative'] = owned[1]
            proof = self._call(source, request)
        source_report, destination_report = self.scanner(source), self.scanner(destination)
        validate_source(source_report, spec, owned=proof)
        forbidden = set(context.get('forbidden_ports', [])) | {context['destination']['port']}
        forbidden.update(self._call(destination, {'action': 'controls'}))
        validate_target(destination_report, spec, forbidden_ports=forbidden)
        listeners = [row for row in destination_report['listeners'] if
                     target_listener(row, literal_address(spec['target_host']), spec['target_port'])]
        return {**parent, 'target_listener_sha256': fingerprint(listeners),
                'owned_worker_pid': proof['pid'] if proof else None}

    def inspect(self, context, spec, owned=None):
        with self._remotes(context) as remotes:
            return self._inspect_locked(context, spec, remotes, owned)

    def observe(self, context, runtime):
        validate_metadata(runtime)
        with self._remotes(context, destination=False) as remotes:
            return self._call(remotes[context['source']['id']], {'action': 'observe', 'runtime': runtime})

    def apply(self, context, runtime, inspection, persist, previous=None):
        validate_metadata(runtime)
        programs = {name: base64.b64encode(data).decode() for name, data in program_bytes().items()}
        validate_programs(runtime, programs)  # Never silently apply a different package after API upgrade.
        with self._remotes(context) as remotes:
            if self._inspect_locked(context, self._spec(runtime), remotes, [previous, runtime] if previous else None) != inspection:
                raise ForwardBlocked('service_inspection_changed')
            node = context['source']['id']
            for kind, key in [('service', runtime['service']), ('directory', runtime['directory']),
                              ('directory', runtime['code_directory']), ('reservation', 'tp-' + str(runtime['nonce']) + '-0')]:
                persist(node, kind, key)
            request = {'action': 'apply', 'runtime': runtime, 'programs': programs,
                       'parent': self._parent(context),
                       'inspection': {key: inspection[key] for key in ('parent_pid', 'parent_config_sha256')}}
            if previous:
                request.update(action='update', runtime=previous, candidate=runtime)
            return self._call(remotes[node], request)

    def stop(self, context, runtime, alternative=None):
        validate_metadata(runtime)
        with self._remotes(context, destination=False) as remotes:
            request = {'action': 'stop', 'runtime': runtime}
            if alternative:
                validate_metadata(alternative)
                request['alternative'] = alternative
            result = self._call(remotes[context['source']['id']], request)
            if result != {'stopped': True}:
                raise ForwardBlocked('service_cleanup_not_verified')
