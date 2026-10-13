"""Real custom-engine pair bodies; no binary-help or carrier-only success."""
import json
import secrets
import shlex


def hedioum_configs(host, transport_port, socks_port, token, interface, tun):
    server = {"role": "foreign", "auth_token": token, "egress_ip_mode": "dual",
              "http_decoy_port": -1, "mimics": [{"type": "tls", "port": transport_port,
              "server_name": "hedioum.test"}]}
    node = {"alias": interface, "target_ip": host, "target_port": transport_port,
            "local_socks_port": socks_port, "socks_bind": "127.0.0.1", "auth_token": token,
            "endpoints": [{"target": f"{host}:{transport_port}", "mimic": "tls",
                           "server_name": "hedioum.test"}],
            "min_connections": 2, "max_connections": 4, "bandwidth_limit_mbps": 100,
            "bandwidth_jitter_mbps": 1, "tun_enabled": tun, "tun_name": interface,
            "tun_addr": "10.244.253.1/24", "dns_enabled": False}
    return server, {"role": "iran", "foreign_nodes": [node]}



def install_hedioum(remote):
    # The release contains self-sufficient binaries, not an install script.
    remote.run(r'''set -Eeuo pipefail
if command -v hedioum >/dev/null; then exit 0; fi
if test -x /opt/multitunnel/bin/hedioum; then
  install -m 0755 /opt/multitunnel/bin/hedioum /usr/local/bin/hedioum; exit 0
fi
python3 - <<'PYBIN'
import hashlib,json,pathlib,platform,urllib.request
name={'x86_64':'hedioum-tunnel','aarch64':'hedioum-tunnel-arm64','armv7l':'hedioum-tunnel-armv7'}.get(platform.machine())
if not name: raise RuntimeError('unsupported Hedioum architecture')
req=urllib.request.Request('https://api.github.com/repos/DashSaman/Hedioum-Pool-Tunnel/releases/latest',headers={'User-Agent':'TunnelPannel'})
release=json.load(urllib.request.urlopen(req,timeout=30))
asset=next(a for a in release['assets'] if a['name']==name)
data=urllib.request.urlopen(asset['browser_download_url'],timeout=120).read()
digest=asset.get('digest')
if digest and digest!='sha256:'+hashlib.sha256(data).hexdigest(): raise RuntimeError('Hedioum digest mismatch')
path=pathlib.Path('/usr/local/bin/hedioum');path.write_bytes(data);path.chmod(0o755)
PYBIN
''', root=True, timeout=180)


def deploy_hedioum(method, run, item, config, a, b, endpoint_a, endpoint_b):
    from plan_executor import executor as bodies
    for remote in (a, b):
        install_hedioum(remote)
    name = f"netauto-hedioum-{run['id']}-{item['id']}"
    interface = bodies.short_name("hdt", run['id'], item['id'])
    transport_port = bodies.free_port(b, "tcp", 22000)
    socks_port = bodies.free_port(a, "tcp", 22000)
    server, hub = hedioum_configs(endpoint_b['host'], transport_port, socks_port,
                                  secrets.token_hex(32), interface, method == "HEDIOUM_TUN")
    directory = f"/etc/netauto/hedioum/{name}"
    services = [name + '-client', name + '-server']
    for remote, document, service in ((b, server, services[1]), (a, hub, services[0])):
        bodies.write_remote_text(remote, directory + '/hedioum.json', json.dumps(document), "0600")
        remote.run("mkdir -p /etc/hedioum", root=True)
        # Its upstream config path is fixed for root. A private mount namespace
        # supplies our owned directory without replacing an operator's config.
        child = f"mount --bind {shlex.quote(directory)} /etc/hedioum; cd {shlex.quote(directory)}; exec /usr/local/bin/hedioum -foreground"
        command = "exec unshare --mount --propagation private /bin/bash -c " + shlex.quote(child)
        bodies.persistent_service(remote, service, command)
    bodies.wait_listener(b, "tcp", transport_port)
    bodies.wait_listener(a, "tcp", socks_port)
    if method == "HEDIOUM_TUN":
        a.run(f"for i in $(seq 1 20); do ip link show {interface} >/dev/null 2>&1 && exit 0; sleep .5; done; exit 1", root=True, timeout=15)
    return {"method": method, "interface_name": interface if method == "HEDIOUM_TUN" else None,
            "local_socks_port": socks_port, "client_side": "A", "server_side": "B",
            "services_a": [services[0]], "services_b": [services[1]],
            "files_a": [directory], "files_b": [directory],
            "interfaces_a": [interface] if method == "HEDIOUM_TUN" else [],
            "transport": "Hedioum authenticated TLS connection pool",
            "tun_provider": "Hedioum native TUN" if method == "HEDIOUM_TUN" else None,
            "carrier_service": services[0] if method == "HEDIOUM_TUN" else None}
