"""Real custom-engine pair bodies; no binary-help or carrier-only success."""
import json
import secrets
import shlex

HEDIOUM_VERSION = 'v0.11.3-pv1'
HEDIOUM_RUNTIME = '/opt/tunnelpannel-engines/hedioum/' + HEDIOUM_VERSION + '/hedioum'


def hedioum_configs(host, transport_port, socks_port, token, interface, tun, *, mimics=None):
    mimics = mimics or [('tls', transport_port)]
    authority = '[' + host + ']' if ':' in host else host
    server = {"role": "foreign", "auth_token": token, "egress_ip_mode": "dual",
              "http_decoy_port": -1, "mimics": [{"type": kind, "port": port,
              "server_name": "hedioum.test"} for kind, port in mimics]}
    node = {"alias": interface, "target_ip": host, "target_port": transport_port,
            "local_socks_port": socks_port, "socks_bind": "127.0.0.1", "auth_token": token,
            "endpoints": [{"target": f"{authority}:{port}", "mimic": kind,
                           "server_name": "hedioum.test"} for kind, port in mimics],
            "min_connections": 2, "max_connections": 4, "bandwidth_limit_mbps": 100,
            "bandwidth_jitter_mbps": 1, "tun_enabled": tun, "tun_name": interface,
            "tun_addr": "10.244.253.1/24", "dns_enabled": False}
    return server, {"role": "iran", "foreign_nodes": [node]}



def install_hedioum(remote):
    # Preserve operator binaries; recipes use an immutable, verified cache.
    remote.run(r'''set -Eeuo pipefail
python3 - <<'PYBIN'
import hashlib,pathlib,platform,urllib.request,os
assets={'x86_64':('hedioum-tunnel','e39a0672ea504b2171eff674a3fedc57adc26b38e39def1f41bc38b859011a3c'),
        'aarch64':('hedioum-tunnel-arm64','721483d57a74f168be0486ff85ec57f9364a2d21542d100de55e50690205bff9')}
if platform.machine() not in assets: raise RuntimeError('pinned Hedioum release supports amd64/arm64 only')
name,expected=assets[platform.machine()]
path=pathlib.Path('__RUNTIME__')
def verified(candidate):
 return candidate.is_file() and hashlib.sha256(candidate.read_bytes()).hexdigest()==expected
if not verified(path):
 candidates=[pathlib.Path('/usr/local/bin/hedioum'),pathlib.Path('/opt/multitunnel/bin/hedioum')]
 cached=next((p for p in candidates if verified(p)),None)
 data=cached.read_bytes() if cached else urllib.request.urlopen('https://github.com/DashSaman/Hedioum-Pool-Tunnel/releases/download/__VERSION__/'+name,timeout=120).read()
 if hashlib.sha256(data).hexdigest()!=expected: raise RuntimeError('Hedioum pinned digest mismatch')
 path.parent.mkdir(parents=True,exist_ok=True)
 temporary=path.with_name('hedioum.next');temporary.write_bytes(data);temporary.chmod(0o755);os.replace(temporary,path)
PYBIN
'''.replace('__RUNTIME__', HEDIOUM_RUNTIME).replace('__VERSION__', HEDIOUM_VERSION), root=True, timeout=180)
    return HEDIOUM_RUNTIME


def deploy_hedioum(method, run, item, config, a, b, endpoint_a, endpoint_b):
    from plan_executor import executor as bodies
    for remote in (a, b):
        install_hedioum(remote)
    name = f"netauto-hedioum-{run['id']}-{item['id']}"
    interface = bodies.short_name("hdt", run['id'], item['id'])
    transport_port = bodies.free_port(b, "tcp", 22000)
    socks_port = bodies.free_port(a, "tcp", 22000)
    suffix = method.removeprefix('HEDIOUM_POOL_').lower()
    kinds = ['tls', 'ssh', 'smtp'] if suffix == 'mixed' else [suffix if suffix in {'ssh', 'smtp', 'imap', 'postgres', 'mysql'} else 'tls']
    mimics = []
    for index, kind in enumerate(kinds):
        port = transport_port if index == 0 else bodies.free_port(b, 'tcp', transport_port + index)
        # Reserve the port before the next scan so adjacent allocations cannot
        # choose the same still-unbound candidate during a mixed-pool setup.
        if port in {value for _, value in mimics}:
            port = bodies.free_port(b, 'tcp', max(value for _, value in mimics) + 1)
        mimics.append((kind, port))
    server, hub = hedioum_configs(endpoint_b['host'], transport_port, socks_port,
                                  secrets.token_hex(32), interface, method == "HEDIOUM_TUN", mimics=mimics)
    directory = f"/etc/netauto/hedioum/{name}"
    services = [name + '-client', name + '-server']
    for remote, document, service in ((b, server, services[1]), (a, hub, services[0])):
        bodies.write_remote_text(remote, directory + '/hedioum.json', json.dumps(document), "0600")
        remote.run("mkdir -p /etc/hedioum", root=True)
        # Its upstream config path is fixed for root. A private mount namespace
        # supplies our owned directory without replacing an operator's config.
        child = f"mount --bind {shlex.quote(directory)} /etc/hedioum; cd {shlex.quote(directory)}; exec {HEDIOUM_RUNTIME} -foreground"
        command = "exec unshare --mount --propagation private /bin/bash -c " + shlex.quote(child)
        bodies.persistent_service(remote, service, command)
    for _, port in mimics:
        bodies.allow_firewall_port(b, port, 'tcp')
        bodies.wait_listener(b, "tcp", port)
    bodies.wait_listener(a, "tcp", socks_port)
    if method == "HEDIOUM_TUN":
        a.run(f"for i in $(seq 1 20); do ip link show {interface} >/dev/null 2>&1 && exit 0; sleep .5; done; exit 1", root=True, timeout=15)
    return {"method": method, "interface_name": interface if method == "HEDIOUM_TUN" else None,
            "local_socks_port": socks_port, "client_side": "A", "server_side": "B",
            "services_a": [services[0]], "services_b": [services[1]],
            "files_a": [directory], "files_b": [directory],
            "interfaces_a": [interface] if method == "HEDIOUM_TUN" else [],
            "transport": "Hedioum authenticated connection pool: " + ', '.join(kinds),
            "mimics": [kind for kind, _ in mimics],
            "tun_provider": "Hedioum native TUN" if method == "HEDIOUM_TUN" else None,
            "carrier_service": services[0] if method == "HEDIOUM_TUN" else None}
