"""Warm owned pair deployments exposing TCP egress through the real carrier."""
from pathlib import Path
import ipaddress
import json
import secrets

from core.catalog import CATALOG
from orchestrator.mesh_campaign import capability
from orchestrator.pair_runtime import RealPairAdapter


def egress_supported(method):
    return (method in CATALOG.identities and capability(method) != 'udp_forward'
            and method not in {'HEDIOUM_TUN', 'SINGBOX_TUN', 'HAJSAMAN_FULL', 'GOST_UDP_FORWARD',
                               'GOST_REMOTE_UDP', 'SSH_UDP_OVER_TCP'})


class PersistentPairAdapter(RealPairAdapter):
    def __init__(self, *args, route_id, **kwargs):
        super().__init__(*args, persistent=True, **kwargs)
        self.route_id = route_id
        self.egress = None

    def _egress(self, host):
        from plan_executor import executor as bodies
        b = self.remotes[1]
        directory = f'/var/lib/tunnelpannel/mesh/{self.route_id}/{self.candidate.legacy_method_id}'
        unit = f'tpmesh-{self.run["id"]}-{self.item["id"]}-egress'
        port = bodies.free_port(b, 'tcp', 25000)
        config = {'listen_host': host, 'listen_port': port, 'username': 'tpmesh',
                  'password': secrets.token_urlsafe(32)}
        self.journals[1].record('path', directory)
        script = Path(__file__).with_name('mesh_gateway.py').read_text(encoding='utf-8')
        bodies.write_remote_text(b, directory + '/gateway.py', script, '0600')
        bodies.write_remote_text(b, directory + '/egress.json', json.dumps(config), '0600')
        bodies.persistent_service(b, unit, f'exec python3 {directory}/gateway.py --egress {directory}/egress.json')
        bodies.wait_listener(b, 'tcp', port)
        self.egress = config
        return config

    def prepare_deployment(self, config, bodies):
        if capability(self.candidate.legacy_method_id) == 'tcp_forward':
            host = self.access[1][0]['host'] if self.candidate.legacy_method_id == 'GOST_TCP_FORWARD' else '127.0.0.1'
            self._egress(host)

    def prepare_forward_target(self, config):
        if self.egress:
            config.update(target_host=self.egress['listen_host'], target_port=self.egress['listen_port'],
                          local_host=self.egress['listen_host'], local_port=self.egress['listen_port'])

    def upstream(self):
        from plan_executor import executor as bodies
        method = self.candidate.legacy_method_id
        if not egress_supported(method):
            raise RuntimeError('this profile needs a dedicated persistent egress adapter')
        if not self.origins:
            self._origins(bodies)
        artifact = self.artifact
        if artifact.get('tunnel_ip_b'):
            host = str(ipaddress.ip_interface(artifact['tunnel_ip_b']).ip)
            egress = self._egress(host)
            upstream = {'host': host, 'port': egress['listen_port'],
                        'username': egress['username'], 'password': egress['password']}
        elif artifact.get('local_socks_port') or 'SOCKS' in method:
            if artifact.get('client_side', 'A') != 'A':
                raise RuntimeError('SOCKS client must be on the route source')
            port = artifact.get('local_socks_port') or artifact.get('listen_port') or artifact.get('listener_port')
            if not port:
                raise RuntimeError('SOCKS endpoint was not returned by the engine')
            upstream = {'host': '127.0.0.1', 'port': port}
            if artifact.get('socks_username'):
                upstream.update(username=artifact['socks_username'], password=artifact['socks_password'])
        elif self.egress:
            side = artifact.get('listener_side') or artifact.get('listen_side') or artifact.get('server_side')
            port = artifact.get('listen_port') or artifact.get('listener_port') or artifact.get('remote_port') or artifact.get('local_port')
            if side != 'A' or not port:
                raise RuntimeError('stream forward must expose an owned listener on the route source')
            upstream = {'host': '127.0.0.1', 'port': port, 'username': self.egress['username'],
                        'password': self.egress['password']}
        else:
            raise RuntimeError('no genuine TCP egress path for this profile')
        origin = self.origins[1]
        probe_host = self.access[1][0]['host'] if method.startswith('HEDIOUM_') else '127.0.0.1'
        return {**upstream, 'id': method, 'probe': {'host': probe_host, 'port': origin[1], 'nonce': origin[2]}}

    def detach(self):
        for remote in self.remotes:
            remote.close()
        for lease in reversed(self.acquired):
            lease.release()
        self.remotes, self.acquired = [], []
