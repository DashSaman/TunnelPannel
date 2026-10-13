"""GOST proxy profiles with an authenticated remote hop and local entry point."""
import shlex
from urllib.parse import urlencode


def deploy_gost_proxy_pair(method, run, item, config, a, b, endpoint_a, endpoint_b):
    from plan_executor import executor as bodies
    schemes = {'GOST_SOCKS5': 'socks5', 'GOST_HTTP': 'http', 'GOST_WS': 'socks5+wss',
               'GOST_HTTP2': 'http2', 'GOST_GRPC': 'socks5+grpc', 'GOST_QUIC': 'socks5+quic',
               'GOST_SSH': 'socks5+ssh', 'GOST_SOCKS5_KCP': 'socks5+kcp'}
    scheme = schemes[method]
    protocol = 'udp' if method in {'GOST_QUIC', 'GOST_SOCKS5_KCP'} else 'tcp'
    for remote in (a, b):
        bodies.install_gost(remote)
    transport = bodies.free_port(b, protocol, 23000)
    local = bodies.free_port(a, 'tcp', 22000)
    name = f"netauto-gost-{run['id']}-{item['id']}"
    username = 'na' + bodies.stable_secret(run['id'], item['id'], 'user', 10)
    password = bodies.stable_secret(run['id'], item['id'], 'pass', 24)
    address = endpoint_b['host']
    authority = f'{username}:{password}@{address}:{transport}'
    server_query, client_query = {}, {}
    tls = None
    if method == 'GOST_SSH':
        # SSH already encrypts each channel. Nested SOCKS TLS closes can set
        # an expired deadline on GOST's shared SSH transport (v3.2.6).
        server_query = {'notls': 'true'}
        client_query = {'notls': 'true'}
    if method in {'GOST_WS', 'GOST_HTTP2', 'GOST_GRPC', 'GOST_QUIC'}:
        tls = bodies.prepare_tls_pair(b, a, name=name, server_host=address, pfx_password='unused')
        server_query = {'certFile': tls['server_cert'], 'keyFile': tls['server_key']}
        client_query = {'caFile': tls['client_ca'], 'secure': 'true', 'serverName': address}
    if method == 'GOST_SOCKS5_KCP':
        key = bodies.stable_secret(run['id'], item['id'], 'kcp-key', 32)
        server_query = client_query = {'kcp.key': key, 'kcp.crypt': 'aes', 'kcp.mode': 'fast'}
    server_url = f'{scheme}://{authority}' + ('?' + urlencode(server_query) if server_query else '')
    client_url = f'{scheme}://{authority}' + ('?' + urlencode(client_query) if client_query else '')
    bodies.allow_firewall_port(b, transport, protocol)
    bodies.persistent_service(b, name + '-server', f'exec /usr/local/bin/gost -L {shlex.quote(server_url)}')
    bodies.wait_listener(b, protocol, transport)
    bodies.persistent_service(a, name + '-client',
        f'exec /usr/local/bin/gost -L socks5://127.0.0.1:{local} -F {shlex.quote(client_url)}')
    bodies.wait_listener(a, 'tcp', local)
    return {'method': method, 'services_a': [name + '-client'], 'services_b': [name + '-server'],
            'files_a': [tls['client_dir']] if tls else [], 'files_b': [tls['server_dir']] if tls else [],
            'listener_side': 'A', 'listen_port': local, 'local_socks_port': local,
            'transport_port': transport, 'transport': scheme, 'certificate_validation': bool(tls),
            'authentication': 'high-entropy-username-password', 'real_pair': True}
