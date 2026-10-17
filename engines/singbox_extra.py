"""Reviewed paired protocols from the repository audit, using sing-box.

ShadowTLS is a transport, so its recipe carries Shadowsocks AEAD 2022.
Every TLS handshake uses the owned destination's CA and hostname.
"""
import base64
import json
import secrets
import shlex
import uuid

METHODS = {'VMESS_TCP_TLS', 'VMESS_WS_TLS', 'ANYTLS', 'SHADOWTLS3_SS2022', 'NAIVE_HTTPS'}


def paired_configs(method, host, port, socks, tls, password, user_uuid, ss_key, cover_port):
    if method not in METHODS:
        raise ValueError('unknown reviewed sing-box recipe')
    sin = {'tag': 'proxy-in', 'listen': host, 'listen_port': port}
    cout = {'tag': 'proxy-out', 'server': host, 'server_port': port}
    extra_in, extra_out = [], []
    if method.startswith('VMESS_'):
        sin.update(type='vmess', users=[{'name': 'owned-client', 'uuid': user_uuid, 'alterId': 0}], tls=tls['server'])
        cout.update(type='vmess', uuid=user_uuid, alter_id=0, security='aes-128-gcm', tls=tls['client'])
        if method == 'VMESS_WS_TLS':
            transport = {'type': 'ws', 'path': '/owned-vmess-stream'}
            sin['transport'], cout['transport'] = dict(transport), dict(transport)
    elif method == 'ANYTLS':
        sin.update(type='anytls', users=[{'name': 'owned-client', 'password': password}], tls=tls['server'])
        cout.update(type='anytls', password=password, tls=tls['client'], min_idle_session=0)
    elif method == 'NAIVE_HTTPS':
        sin.update(type='naive', network='tcp', users=[{'username': 'owned-client', 'password': password}], tls=tls['server'])
        # Cronet controls TLS versions; the owned server still requires 1.3.
        client_tls = {k: v for k, v in tls['client'].items() if k != 'min_version'}
        cout.update(type='naive', username='owned-client', password=password, tls=client_tls)
    else:
        sin.update(type='shadowtls', version=3, users=[{'name': 'owned-client', 'password': password}],
                   strict_mode=True, handshake={'server': '127.0.0.1', 'server_port': cover_port}, detour='aead-in')
        extra_in = [{'type': 'shadowsocks', 'tag': 'aead-in', 'method': '2022-blake3-aes-128-gcm',
                     'password': ss_key, 'network': 'tcp'}]
        cout = {'type': 'shadowsocks', 'tag': 'proxy-out', 'server': host, 'server_port': port,
                'method': '2022-blake3-aes-128-gcm', 'password': ss_key, 'detour': 'shadowtls-out'}
        extra_out = [{'type': 'shadowtls', 'tag': 'shadowtls-out', 'server': host, 'server_port': port,
                      'version': 3, 'password': password, 'tls': tls['client']}]
    client = {'log': {'level': 'warn'},
              'inbounds': [{'type': 'socks', 'tag': 'local-in', 'listen': '127.0.0.1', 'listen_port': socks}],
              'outbounds': [cout, *extra_out], 'route': {'final': 'proxy-out'}}
    server = {'log': {'level': 'warn'}, 'inbounds': [sin, *extra_in],
              'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}
    return client, server


def deploy(method, run, item, config, a, b, endpoint_a, endpoint_b):
    from plan_executor import executor as bodies
    for remote in (a, b):
        bodies.install_singbox(remote)
    name = f'netauto-sbextra-{run["id"]}-{item["id"]}'
    directory = '/etc/netauto/sing-box-extra/' + name
    host = endpoint_b['host']
    port, socks = bodies.free_port(b, 'tcp', 24000), bodies.free_port(a, 'tcp', 22000)
    bodies.allow_firewall_port(b, port, 'tcp')
    cover = bodies.free_port(b, 'tcp', 25000)
    certs = bodies.prepare_tls_pair(b, a, name=name, server_host='owned-cover.test', pfx_password='unused', leaf_days=90)
    tls = {'server': {'enabled': True, 'server_name': 'owned-cover.test', 'min_version': '1.3',
                      'certificate_path': certs['server_cert'], 'key_path': certs['server_key']},
           'client': {'enabled': True, 'server_name': 'owned-cover.test', 'min_version': '1.3',
                      'certificate_path': certs['client_ca']}}
    docs = paired_configs(method, host, port, socks, tls, secrets.token_urlsafe(32), str(uuid.uuid4()),
                          base64.b64encode(secrets.token_bytes(16)).decode(), cover)
    units_a, units_b = [name + '-client'], [name + '-server']
    if method == 'SHADOWTLS3_SS2022':
        unit = name + '-cover'
        units_b.append(unit)
        bodies.persistent_service(b, unit, f'exec openssl s_server -accept 127.0.0.1:{cover} -tls1_3 '
            f'-cert {shlex.quote(certs["server_cert"])} -key {shlex.quote(certs["server_key"])} -www -quiet')
        bodies.wait_listener(b, 'tcp', cover)
    for remote, doc, unit in ((b, docs[1], units_b[0]), (a, docs[0], units_a[0])):
        path = directory + '/config.json'
        bodies.write_remote_text(remote, path, json.dumps(doc), '0600')
        bodies.validate_json_service(remote, 'sing-box', path)
        bodies.persistent_service(remote, unit, 'exec sing-box run -c ' + shlex.quote(path))
        bodies.wait_listener(remote, 'tcp', port if remote is b else socks)
    return {'method': method, 'engine': 'singbox', 'client_side': 'A', 'server_side': 'B',
            'local_socks_port': socks, 'server_host': host, 'server_port': port,
            'services_a': units_a, 'services_b': units_b, 'files_a': [directory, certs['client_dir']],
            'files_b': [directory, certs['server_dir']], 'certificate_validation': True,
            'authenticated_transport': True}
