"""Two-node HajSaman native stack, matching the TunnelGuard implementation.

FULL additionally proves Xray's socket mark, WG-over-SIT, forwarding and SNAT
against an owned network-namespace origin. It needs no external benchmark host.
"""
import ipaddress
import json
import secrets
import shlex


def full_xray_config(port, mark):
    return {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1",
            "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [{"protocol": "freedom", "settings": {},
                           "streamSettings": {"sockopt": {"mark": mark}}}]}


def deploy_hajsaman(method, run, item, config, a, b, endpoint_a, endpoint_b, journals):
    from plan_executor import executor as bodies
    from orchestrator.host_lease import unused_prefix
    inner6 = ipaddress.ip_network(unused_prefix((a, b), version=6))
    sit_cfg = {**config, 'tunnel_cidr': str(inner6),
               'tunnel_ip_a': f'{inner6[1]}/64', 'tunnel_ip_b': f'{inner6[2]}/64'}
    sit = bodies.deploy_kernel('SIT_6IN4', run, {'id': item['id'] * 100 + 31}, sit_cfg, a, b)
    for side in ('a', 'b'):
        sit['services_' + side] = [sit['systemd_unit']]
        sit['interfaces_' + side] = [sit['interface_name']]
    sit['mtu'] = 1480
    for remote in (a, b):
        remote.run(f"ip link set {sit['interface_name']} mtu 1480", root=True)
    if method == 'HAJSAMAN_SIT':
        return {**sit, 'method': method, 'stack': ['sit']}
    wg_cfg = {**config, 'source_ip_a': str(ipaddress.ip_interface(sit_cfg['tunnel_ip_a']).ip),
              'source_ip_b': str(ipaddress.ip_interface(sit_cfg['tunnel_ip_b']).ip)}
    wg = bodies.deploy_wireguard(run, {'id': item['id'] * 100 + 32}, wg_cfg, a, b)
    for side in ('a', 'b'):
        wg['services_' + side] = [f"wg-quick@{wg['interface_name']}"]
        wg['interfaces_' + side] = [wg['interface_name']]
        wg['files_' + side] = [f"/etc/wireguard/{wg['interface_name']}.conf"]
    for remote in (a, b):
        remote.run(f"ip link set {wg['interface_name']} mtu 1400", root=True)
    artifact = bodies.merge_component_artifacts(method, [sit, wg], wg)
    artifact.update(interface_name=wg['interface_name'], carrier_interface=sit['interface_name'],
                    stack=['sit', 'wireguard'])
    if method != 'HAJSAMAN_FULL':
        return artifact
    tag = f"tpbench-{run['id']}-{item['id']}-haj"
    namespace = bodies.short_name('hns', run['id'], item['id'])
    veth = bodies.short_name('hv', run['id'], item['id'])
    ns_peer = bodies.short_name('hp', run['id'], item['id'])
    namespace_net = ipaddress.ip_network(unused_prefix((a, b), exclude=[config['tunnel_cidr']]))
    origin, gateway = str(namespace_net[2]), str(namespace_net[1])
    source = str(ipaddress.ip_interface(wg['tunnel_ip_a']).ip)
    payload = secrets.token_hex(24)
    directory = f'/var/lib/tunnelpannel/bench/{tag}'
    port = bodies.free_port(b, 'tcp', 25000)
    socks = bodies.free_port(a, 'tcp', 22000)
    from orchestrator.route_allocation import free_priority, free_table
    table = free_table(a, 52000 + run['id'] % 8000)
    priority = free_priority(a)
    if namespace in b.run('ip netns list')['stdout'].split():
        raise RuntimeError('owned HajSaman namespace name already exists')
    journals[1].record('cleanup_command', f'ip netns del {namespace} 2>/dev/null || true')
    forward = b.run('sysctl -n net.ipv4.ip_forward')['stdout'].strip()
    if forward != '1':
        journals[1].record('cleanup_command', f'sysctl -w net.ipv4.ip_forward={int(forward)} >/dev/null')
        b.run('sysctl -w net.ipv4.ip_forward=1', root=True)
    b.run(f'ip netns add {namespace}; ip link add {veth} type veth peer name {ns_peer}; '
          f'ip link set {ns_peer} netns {namespace}; ip addr add {gateway}/30 dev {veth}; '
          f'ip link set {veth} up; ip netns exec {namespace} ip addr add {origin}/30 dev {ns_peer}; '
          f'ip netns exec {namespace} ip link set {ns_peer} up; '
          f'ip netns exec {namespace} ip link set lo up; '
          f'ip netns exec {namespace} ip route add default via {gateway}', root=True)
    nat = f'-s {source}/32 -d {origin}/32 -o {veth} -m comment --comment {tag} -j SNAT --to-source {gateway}'
    journals[1].record('cleanup_command', f'iptables -t nat -D POSTROUTING {nat} 2>/dev/null || true')
    b.run(f'iptables -t nat -A POSTROUTING {nat}', root=True)
    for remote in (a, b):
        iface = wg['interface_name']
        peers = remote.run(f'wg show {iface} peers')['stdout'].split()
        if len(peers) != 1:
            raise RuntimeError('owned WG slot must have exactly one peer')
        peer_inner = str(ipaddress.ip_interface(wg['tunnel_ip_b' if remote is a else 'tunnel_ip_a']).ip)
        allowed = peer_inner + '/32' + (',' + origin + '/32' if remote is a else '')
        remote.run(f'wg set {iface} peer {peers[0]} allowed-ips {allowed}', root=True)
        remote.run("sed -i " + shlex.quote(f's|^AllowedIPs =.*|AllowedIPs = {allowed}|')
                   + f' /etc/wireguard/{iface}.conf', root=True)
    journals[0].record('cleanup_command', f'ip rule del priority {priority} fwmark {table} lookup {table} 2>/dev/null || true')
    journals[0].record('cleanup_command', f'ip route flush table {table}')
    a.run(f'ip route add {origin}/32 dev {wg["interface_name"]} table {table}; '
          f'ip route add blackhole default table {table}; ip rule add priority {priority} fwmark {table} lookup {table}', root=True)
    b.run(f"install -d -m 700 {directory}; printf '%s' {payload} > {directory}/index.html; "
          f'systemd-run --collect --unit={tag}-origin --property=RuntimeMaxSec=3600 '
          f'ip netns exec {namespace} python3 -m http.server {port} --bind {origin} --directory {directory}', root=True)
    bodies.install_xray(a)
    xray_path = f'/etc/netauto/hajsaman/{tag}.json'
    bodies.write_remote_text(a, xray_path, json.dumps(full_xray_config(socks, table)), '0600')
    bodies.persistent_service(a, tag + '-xray', f'exec /usr/local/bin/xray run -config {shlex.quote(xray_path)}')
    bodies.wait_listener(a, 'tcp', socks)
    artifact.update(stack=['sit', 'wireguard', 'xray_mark', 'policy_route', 'snat'],
                    full_origin=origin, full_origin_port=port, full_payload=payload,
                    full_directory=directory,
                    local_socks_port=socks, nat_comment=tag, policy_mark=table)
    artifact['services_a'].append(tag + '-xray')
    return artifact
