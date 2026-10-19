"""Canonical real-pair benchmark adapter, reusing existing deployment bodies.

Each adapter owns a unique run/item namespace. Pair locks prevent simultaneous
routing mutations on a node. SSH credentials are resolved from encrypted node
records; request-provided capabilities and network commands are never trusted.
"""
from __future__ import annotations

import ipaddress
import json
import re
import secrets
import shlex
import time

from fastapi import HTTPException

from core.catalog import CATALOG
from core.models import NodeInventory
from engines.adapters import ProbeResult
from orchestrator.benchmarking import PROFILES, Candidate, NodeCaps
from orchestrator.remote_nodes import NodeRemote, node_access


def traffic_plan(method):
    reverse = (method.startswith(("FRP_", "RATHOLE_", "BACKHAUL_")) or "REVERSE" in method
               or method in {"SSH_REMOTE_FORWARD", "GOST_REMOTE_TCP", "GOST_REMOTE_UDP"})
    return {"initiator": "B" if reverse else "A", "origin_index": 1, "listener_side": "A"}


def carrier_details(artifact):
    component = artifact['components'][0]
    interface = component.get('interface_name') or next(iter(component.get('interfaces_a', [])), None)
    units = component.get('services_a') or ([component['systemd_unit']] if component.get('systemd_unit') else [])
    if not interface or not units:
        raise RuntimeError('carrier must identify its own interface and service')
    return interface, units



def stop_owned_transient(remote,service):
    unit=shlex.quote(service.removesuffix('.service')+'.service')
    remote.run(f'systemctl stop {unit}',root=True,timeout=20,check=False)
    state=remote.run(f'systemctl is-active {unit}',root=True,timeout=10,check=False)
    if state['code'] not in (3,4) or state['stdout'].strip() not in ('inactive','failed','unknown'):
        raise RuntimeError('owned transient did not stop: '+service)


def prepare_benchmark(session_factory):
    def prepare(req):
        a_id, b_id = req.node_a.get("node_id"), req.node_b.get("node_id")
        if not a_id or not b_id or a_id == b_id:
            raise HTTPException(400, "select two distinct registered nodes")
        access, caps = [], []
        with session_factory() as s:
            for node_id in (a_id, b_id):
                try:
                    access.append(node_access(s, node_id))
                except ValueError as e:
                    raise HTTPException(400, str(e)) from None
                row = (s.query(NodeInventory).filter_by(node_id=node_id)
                       .order_by(NodeInventory.collected_at.desc()).first())
                if row is None:
                    raise HTTPException(400, "discover each registered node before benchmarking")
                snapshot = row.snapshot
                ipv6 = snapshot.get("ipv6_addresses", "").split()
                if "inet6" in ipv6:
                    access[-1][0]["ipv6"] = ipv6[ipv6.index("inet6") + 1].split("/")[0]
                caps.append(NodeCaps(node_id=node_id, os=snapshot["os"], arch=snapshot["arch"],
                                     privileged=snapshot["privileged"], binaries=set(snapshot["binaries"]),
                                     kernel_modules=set(snapshot["kernel_modules"])))
        candidates = []
        identifiers = list(CATALOG.identities.values())
        allowed = {i.legacy_id for i in identifiers}
        if req.methods and not set(req.methods) <= allowed:
            raise HTTPException(400, "unknown method in selection")
        for ident in identifiers:
            if req.methods and ident.legacy_id not in req.methods:
                continue
            if not req.methods and ident.is_composite:
                continue
            compatible = all(c.os == "linux" and c.privileged for c in caps)
            candidates.append(Candidate(ident.engine, ident.profile, ident.legacy_id, ident.family,
                                        "COMPATIBLE" if compatible else "INCOMPATIBLE",
                                        "" if compatible else "real deployment requires Linux root/sudo access"))
        nonce = secrets.randbelow(900_000_000) + 100_000_000
        numbers = {c.legacy_method_id: index + 1 for index, c in enumerate(candidates)}
        def factory(candidate):
            return RealPairAdapter(candidate, access, req.profile, nonce,
                                   numbers[candidate.legacy_method_id])
        from orchestrator.engine_preflight import prepare_engines
        factory.prepare = lambda candidates, cancelled: prepare_engines(access, candidates, cancelled)
        return caps[0], caps[1], candidates, factory
    return prepare


class RealPairAdapter:
    def __init__(self, candidate, access, profile, nonce, item, *, persistent=False):
        self.candidate, self.access = candidate, access
        self.persistent = persistent
        self.profile = PROFILES[profile]
        self.run, self.item = {"id": nonce}, {"id": item, **traffic_plan(candidate.legacy_method_id)}
        self.tag = f"tpbench-{nonce}-{item}"
        self.remotes = []
        self.acquired = []
        self.artifact = None
        self.origins = []
        self.extra_services = []
        self.observations = {}
        self.measurements = {}
        self.journals = []
        self.management_routes = []
        self.http_flow = None
        self.udp_flow = None
        self.carrier_verified = False
        self.persist_resource = lambda *args: None
        self.cancelled = lambda: False

    def bind(self, persist_resource, cancelled=None):
        self.persist_resource = persist_resource
        self.cancelled = cancelled or self.cancelled

    def configure(self):
        from plan_executor import executor as bodies
        endpoints = [v[0] for v in self.access]
        from orchestrator.host_lease import HostLease, unused_prefix
        locks = sorted({HostLease(e).key: HostLease(e) for e in endpoints}.values(), key=lambda l: l.key)
        if len(locks) != 2:
            raise RuntimeError("benchmark endpoints must be distinct physical hosts")
        for lock in locks:
            deadline = time.monotonic() + self.profile.setup_timeout_s
            while not lock.acquire(timeout=.5):
                if self.cancelled():
                    raise RuntimeError("benchmark cancelled")
                if time.monotonic() >= deadline:
                    raise TimeoutError("another benchmark is using these nodes")
            self.acquired.append(lock)
        deadline = time.monotonic() + self.profile.overall_timeout_s
        for endpoint, credentials in self.access:
            remote = NodeRemote(endpoint, credentials, deadline=deadline, cancelled=self.cancelled).connect()
            self.remotes.append(remote)
            from orchestrator.host_inventory import scan, require_safe
            require_safe(scan(remote), self.candidate.legacy_method_id)
        # Inspect BOTH hosts before creating the first owned reservation journal.
        for remote, (endpoint, _) in zip(self.remotes, self.access):
            from orchestrator.remote_journal import RemoteJournal
            journal = RemoteJournal(remote, self.run["id"], self.item["id"], endpoint["id"],
                                    self.persist_resource)
            self.journals.append(journal)
            remote.journal = journal
            remote.observer = journal.observe
            from orchestrator.host_reservations import initialize
            initialize(remote, journal, self.run['id'], self.item['id'])
        a, b = self.remotes
        for remote, peer in ((a, endpoints[1]['host']), (b, endpoints[0]['host'])):
            remote.firewall_peer = peer
            targets = {peer}
            ssh = remote.run("printf '%s' \"$SSH_CONNECTION\"")['stdout'].split()
            if ssh:
                targets.add(str(ipaddress.ip_address(ssh[0])))
            for target in targets:
                self.management_routes.append((remote, target, self._route(remote, target)))
        # Safe dedicated ranges: no default routes and no existing-resource removal.
        prefix = ipaddress.ip_network(unused_prefix(self.remotes))
        config = {"source_ip_a": endpoints[0]["host"], "source_ip_b": endpoints[1]["host"],
                  "tunnel_cidr": str(prefix), "tunnel_ip_a": f"{prefix[1]}/30",
                  "tunnel_ip_b": f"{prefix[2]}/30", "bind_address": "127.0.0.1",
                  "remote_bind_host": "127.0.0.1", "listen_host": "127.0.0.1",
                  "benchmark_size_mb": 1 if self.profile.name == "QUICK" else 8,
                  "benchmark_enabled": False, "route_cidrs": [endpoints[1]["host"] + "/32"]}
        config["auto_route"] = False  # Port-scoped policy routing preserves SSH to the same peer.
        method = self.candidate.legacy_method_id
        config['ssh_tunnel_id'] = 100000 + (self.run['id'] + self.item['id']) % 800000
        implicit = {'HEDIOUM_TUN': ('hdt', [0]), 'SINGBOX_TUN': ('nsb', [0]),
                    'GOST_TUN': ('ngn', [0, 1]), 'GOST_TAP': ('ngp', [0, 1])}
        if method in implicit:
            prefix, indexes = implicit[method]
            for index in indexes:
                self.journals[index].claim_interface(bodies.short_name(prefix, self.run['id'], self.item['id']))
        if method in {'SSH_TUN_L3', 'SSH_TAP_L2'} or method.endswith('_OVER_SSH'):
            from orchestrator.host_reservations import free_tun_id
            config['ssh_tunnel_id'] = free_tun_id(self.remotes, config['ssh_tunnel_id'])
            name = ('tap' if method == 'SSH_TAP_L2' else 'tun') + str(config['ssh_tunnel_id'])
            for journal in self.journals:
                journal.claim_interface(name)
        if method.endswith('_OVER_GOST'):
            for journal in self.journals:
                journal.claim_interface(bodies.short_name('ngc', self.run['id'], self.item['id']))
        if method == 'SIT_6IN4' or method.startswith('SIT_OVER_'):
            inner6 = ipaddress.ip_network(unused_prefix(self.remotes, version=6))
            config.update(tunnel_cidr=str(inner6), tunnel_ip_a=f"{inner6[1]}/64",
                          tunnel_ip_b=f"{inner6[2]}/64")
        if method in {"IP6GRE", "IP6GRETAP", "VTI6", "IP4IN6"}:
            if not all(e.get("ipv6") for e in endpoints):
                raise RuntimeError("this profile requires actual global IPv6 on both nodes")
            config.update(source_ip_a=endpoints[0]["ipv6"], source_ip_b=endpoints[1]["ipv6"])
        self.config = config
        self.prepare_deployment(config, bodies)
        from engines.singbox_extra import METHODS as extra_protocols
        if method not in bodies.SUPPORTED and method not in extra_protocols and not method.startswith(("HEDIOUM_", "HAJSAMAN_", "WATERWALL_H_")):
            raise RuntimeError(f"real deployment body is required for {method}")
        if method in extra_protocols:
            from engines.singbox_extra import deploy
            self._origins(bodies)
            self.artifact = deploy(method, self.run, self.item, config, a, b, *endpoints)
        elif method.startswith('WATERWALL_H_'):
            from engines.waterwall_h import deploy
            self._origins(bodies)
            self.target_origin = self.origins[1]
            config.update(target_port=self.target_origin[1])
            self.prepare_forward_target(config)
            self.artifact = deploy(method, self.run, self.item, config, a, b, *endpoints)
        elif method.startswith("HAJSAMAN_"):
            from engines.hajsaman_pair import deploy_hajsaman
            self.artifact = deploy_hajsaman(method, self.run, self.item, config, a, b,
                                            *endpoints, self.journals)
        elif method in {'GOST_SOCKS5', 'GOST_HTTP', 'GOST_WS', 'GOST_HTTP2', 'GOST_GRPC',
                        'GOST_QUIC', 'GOST_SSH', 'GOST_SOCKS5_KCP'}:
            self._origins(bodies)
            self.target_origin = self.origins[1]
            from engines.gost_pair import deploy_gost_proxy_pair
            self.artifact = deploy_gost_proxy_pair(method, self.run, self.item, config, a, b, *endpoints)
        elif method == 'AMNEZIAWG':
            from engines.amneziawg import deploy
            self.artifact = deploy(self.run, self.item, config, a, b)
        elif method == "WIREGUARD":
            self.artifact = bodies.deploy_wireguard(self.run, self.item, config, a, b)
        elif method in {"GRE", "GRETAP", "IPIP", "SIT_6IN4", "IP6GRE", "IP6GRETAP", "VXLAN", "IP4IN6"}:
            self.artifact = bodies.deploy_kernel(method, self.run, self.item, config, a, b)
        else:
            self._origins(bodies, http_bind='::' if ipaddress.ip_interface(config['tunnel_ip_b']).version == 6 else '0.0.0.0')
            if method in {"VLESS_REALITY", "VLESS_VISION_REALITY", "VLESS_XHTTP_REALITY"}:
                cover_port = bodies.free_port(b, "tcp", 23000)
                cover_dir = f"/etc/netauto/reality/{self.tag}"
                cover_service = f"{self.tag}-cover"
                b.run(f"install -d -m 700 {cover_dir}; openssl req -x509 -newkey ec "
                      f"-pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 "
                      f"-subj '/CN=cover.test' -addext 'subjectAltName=DNS:cover.test' "
                      f"-keyout {cover_dir}/key.pem -out {cover_dir}/cert.pem >/dev/null 2>&1; "
                      f"chmod 600 {cover_dir}/key.pem", root=True)
                self.extra_services.append((b, cover_service))
                bodies.persistent_service(b, cover_service,
                    f"exec openssl s_server -accept 127.0.0.1:{cover_port} -tls1_3 "
                    f"-cert {cover_dir}/cert.pem -key {cover_dir}/key.pem -alpn h2,http/1.1 -www -quiet")
                bodies.wait_listener(b, "tcp", cover_port)
                config.update(reality_target=f"127.0.0.1:{cover_port}", reality_server_name="cover.test")
            self.target_origin = self.origins[1]
            config.update(target_host="127.0.0.1", target_port=self.target_origin[1],
                          local_port=self.target_origin[1], local_host="127.0.0.1")
            self.prepare_forward_target(config)
            if method == 'BACKHAUL_TCP':
                from engines.backhaul import deploy
                self.artifact = deploy(self.run, self.item, config, a, b, *endpoints)
                self._check_management_routes()
                return
            if "UDP" in method:
                config.update(target_port=self.target_origin[5], local_port=self.target_origin[5])
            if method in {"GOST_TCP_FORWARD", "GOST_UDP_FORWARD"}:
                if not self.persistent:
                    config.update(target_host=endpoints[1]["host"],
                                  target_port=self.origins[1][5 if "UDP" in method else 1])
            for family, deploy in [(bodies.SSH_METHODS, bodies.deploy_ssh_method),
                (bodies.GOST_METHODS, bodies.deploy_gost_method),
                (bodies.VPN_METHODS, bodies.deploy_vpn_method),
                (bodies.XRAY_METHODS, bodies.deploy_xray_method),
                (bodies.SINGBOX_METHODS, bodies.deploy_singbox_method),
                (bodies.WATERWALL_METHODS, bodies.deploy_waterwall_method),
                (bodies.PAQET_METHODS, bodies.deploy_paqet_method),
                (bodies.COMPOSITE_METHODS, bodies.deploy_composite_method),
                (bodies.FRP_METHODS | bodies.RATHOLE_METHODS | bodies.CHISEL_METHODS | bodies.WSTUNNEL_METHODS,
                 bodies.deploy_pack4_method)]:
                if method in family:
                    self.artifact = deploy(method, self.run, self.item, config, a, b, *endpoints)
                    break
            else:
                if method.startswith("HEDIOUM_"):
                    from engines.custom_pair import deploy_hedioum
                    self.artifact = deploy_hedioum(method, self.run, self.item, config, a, b, *endpoints)
                else:
                    raise RuntimeError("method has no real pair deployment family")
        self._check_management_routes()

    @staticmethod
    def _route(remote, target):
        rows = json.loads(remote.run(f"ip -j route get {shlex.quote(target)}", root=True)['stdout'])
        return [{key: row.get(key) for key in ('dev', 'gateway', 'prefsrc', 'type')} for row in rows]

    def _check_management_routes(self):
        for remote, target, before in self.management_routes:
            if self._route(remote, target) != before:
                raise RuntimeError("deployment changed a management route; rollback required")

    def prepare_deployment(self, config, bodies):
        """Persistent subclasses may provision an owned forwarding target."""

    def prepare_forward_target(self, config):
        """Persistent subclasses may forward a stream to an authenticated egress."""

    def _origins(self, bodies, http_bind="0.0.0.0"):
        for index, remote in enumerate(self.remotes):
            payload = secrets.token_hex(24)
            port = bodies.free_port(remote, "tcp", 25000)
            udp_port = bodies.free_port(remote, "udp", 27000)
            directory = f"/var/lib/tunnelpannel/bench/{self.tag}-{index}"
            service = f"{self.tag}-origin-{index}"
            command = (f"install -d -m 700 {directory}; printf '%s' {payload} > {directory}/index.html; "
                       f"systemd-run --unit={service} --collect --property=RuntimeMaxSec=3600 "
                       f"python3 -m http.server {port} --bind {shlex.quote(http_bind)} --directory {directory}")
            self.origins.append((remote, port, payload, service, directory, udp_port))
            if self.persistent:
                remote.run(f"install -d -m 700 {directory}; printf '%s' {payload} > {directory}/index.html", root=True)
                health_bind = '0.0.0.0' if self.candidate.legacy_method_id.startswith('HEDIOUM_') else '127.0.0.1'
                bodies.persistent_service(remote, service,
                    f"exec python3 -m http.server {port} --bind {health_bind} --directory {directory}")
            else:
                remote.run(command, root=True)
            bodies.wait_listener(remote, "tcp", port)
            if self.persistent:
                continue
            udp_service = service + "-udp"
            script = ("import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                      f"s.bind(('0.0.0.0',{udp_port})); "
                      f"exec(\"while True:\\n d,a=s.recvfrom(65535); s.sendto({(payload+'|').encode()!r}+d,a)\")")
            self.extra_services.append((remote, udp_service))
            remote.run(f"systemd-run --unit={udp_service} --collect --property=RuntimeMaxSec=3600 "
                       f"python3 -c {shlex.quote(script)}", root=True)
            bodies.wait_listener(remote, "udp", udp_port)

    def start(self):
        if not self.artifact:
            raise RuntimeError("deployment did not return a data-plane artifact")

    def probe(self):
        from plan_executor import executor as bodies
        artifact = self.artifact
        a, b = self.remotes
        if self.candidate.legacy_method_id == "HAJSAMAN_FULL":
            return self._probe_hajsaman_full()
        if self.candidate.legacy_method_id in {"HEDIOUM_TUN", "SINGBOX_TUN"}:
            return self._probe_scoped_tun()
        if artifact.get("tunnel_ip_a") and artifact.get("tunnel_ip_b"):
            rows = []
            timings = []
            for remote, target in ((a, artifact["tunnel_ip_b"]), (b, artifact["tunnel_ip_a"])):
                ip = str(ipaddress.ip_interface(target).ip)
                result = remote.run(f"ping -n -c {self.profile.rtt_probes} -i .1 -W 2 {shlex.quote(ip)}",
                                    root=True, timeout=self.profile.probe_timeout_s + 20, check=False)
                rows.append(bodies.parse_ping_metrics(result["stdout"]))
                timings.extend(float(v) for v in re.findall(r'time[=<]([0-9.]+)', result['stdout']))
                if result["code"] or rows[-1]["loss_percent"] >= 100:
                    return ProbeResult(False, "real-pair inner traffic failed")
            self.measurements.update(rtt_avg=sum(r["rtt_avg_ms"] for r in rows) / 2,
                                     loss_pct=max(r["loss_percent"] for r in rows),
                                     jitter=max(r["rtt_jitter_ms"] for r in rows))
            self.observations = {"scope": "REAL_PAIR", "directions": ["a_to_b", "b_to_a"], "ping": rows}
            from orchestrator.benchmarking import rtt_stats
            self.measurements.update(rtt_stats(timings))
            carrier = carrier_details(artifact)[0] if artifact.get('components') else None
            if carrier and not self.carrier_verified:
                target = str(ipaddress.ip_interface(artifact['tunnel_ip_b']).ip)
                command = f'ping -n -c 1 -W 2 {target}'
                blocked, resumed, actions = self._carrier_outage(command)
                self.observations['carrier_outage'] = {'interface': carrier, 'traffic_blocked': blocked,
                                                       'recovered': resumed, 'restoration_actions': actions}
                if not blocked or not resumed:
                    return ProbeResult(False, 'overlay must fail with its carrier down and recover after restoration')
                self.carrier_verified = True
            return ProbeResult(True, "bidirectional inner traffic passed on distinct nodes")
        proxy = artifact.get("proxy_benchmark")
        if proxy and proxy.get("http_code") == 200 and not artifact.get('local_socks_port'):
            self.observations = {"scope": "REAL_PAIR", "proxy_transfer": proxy}
            self.measurements["throughput_mbps"] = proxy.get("mbps") or proxy.get("throughput_mbps")
            return ProbeResult(True, "received measured payload through the real-pair proxy")
        if self.candidate.legacy_method_id.startswith("HEDIOUM_POOL_"):
            origin = self.origins[1]
            url = f"http://{self.access[1][0]['host']}:{origin[1]}/"
            result = a.run(f"curl --noproxy '' -fsS --socks5-hostname 127.0.0.1:{artifact['local_socks_port']} "
                           f"--max-time 20 {shlex.quote(url)}", root=True, timeout=25, check=False)
            ok = result["code"] == 0 and result["stdout"].strip() == origin[2]
            command = f"curl --noproxy '' -fsS --socks5-hostname 127.0.0.1:{artifact['local_socks_port']} --max-time 20 {shlex.quote(url)}"
            self.http_flow = (a, command, origin[0], origin[4], origin[2])
            self.observations = {"scope": "REAL_PAIR", "pool_payload_matched": ok}
            return ProbeResult(ok, "Hedioum pool delivered the remote server's unique payload")
        listener = (artifact.get("listener_port") or artifact.get("listen_port")
                    or artifact.get("remote_port") or artifact.get("local_port") or artifact.get('local_socks_port'))
        side = (artifact.get("listener_side") or artifact.get("listen_side") or
                (artifact.get("client_side") if artifact.get('local_socks_port') or self.candidate.legacy_method_id.startswith(("GOST_KCP", "PAQET_")) else None)
                or artifact.get("server_side") or "B")
        remote = a if side == "A" else b
        if not listener:
            return ProbeResult(False, "artifact has no verified data-plane probe path")
        method = self.candidate.legacy_method_id
        if "UDP" in method:
            challenge = secrets.token_hex(16)
            expected = (self.target_origin[2] + "|" + challenge).encode()
            script = ("import socket,json,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                      "s.settimeout(10); t=time.monotonic(); "
                      f"s.sendto({challenge.encode()!r},('127.0.0.1',{listener})); data,_=s.recvfrom(65535); "
                      f"print(json.dumps({{'matched':data=={expected!r},'rtt_ms':(time.monotonic()-t)*1000}}))")
            result = remote.run("python3 -c " + shlex.quote(script), root=True, timeout=15, check=False)
            import json
            try:
                evidence = json.loads(result["stdout"])
            except ValueError:
                return ProbeResult(False, "real-pair UDP probe timed out or failed")
            ok = result["code"] == 0 and evidence["matched"]
            self.udp_flow = (remote, listener, self.target_origin[2])
            self.observations = {"scope": "REAL_PAIR", "datagram": evidence}
            self.measurements["rtt_avg"] = evidence["rtt_ms"]
            return ProbeResult(ok, "unique server nonce and datagram payload matched" if ok else 'server datagram nonce or payload mismatch')
        if "SOCKS" in method or artifact.get('local_socks_port'):
            origin = self.origins[1 if side == "A" else 0]
            auth = ""
            if artifact.get("socks_username"):
                auth = "--proxy-user " + shlex.quote(artifact['socks_username'] + ':' + artifact['socks_password']) + " "
            args = f"{auth}--socks5-hostname 127.0.0.1:{listener} http://127.0.0.1:{origin[1]}/"
        else:
            # Forward target is a separate origin reached over this tunnel.
            origin = self.target_origin
            args = f"http://127.0.0.1:{listener}/"
        t0 = time.monotonic()
        command = f"curl --noproxy '' -fsS --max-time 15 {args}"
        self.http_flow = (remote, command, origin[0], origin[4], origin[2])
        result = remote.run(command, root=True, check=False)
        ok = result["code"] == 0 and result["stdout"].strip() == origin[2]
        self.measurements["rtt_avg"] = (time.monotonic() - t0) * 1000
        self.observations = {"scope": "REAL_PAIR", "payload_matched": ok,
                             'curl_exit_code': result['code']}
        return ProbeResult(ok, "unique HTTP payload through real-pair forward" if ok else
                           'forward payload mismatch (curl ' + str(result['code']) + ': ' + result['stderr'][:160] + ')')

    def _probe_scoped_tun(self):
        """Route only our HTTP origin port; never route a node's SSH control traffic."""
        from orchestrator.route_allocation import free_priority, free_table
        a = self.remotes[0]
        interface = self.artifact['interface_name']
        host = self.access[1][0]['host']
        origin = self.origins[1]
        table = free_table(a, 30000 + self.run['id'] % 20000)
        priority = free_priority(a)
        user = f"tpb{self.run['id']}{self.item['id']}"
        if a.run(f'id {user}', root=True, check=False)['code'] == 0:
            raise RuntimeError('benchmark probe user already exists')
        journal = self.journals[0]
        journal.record('cleanup_command', f'userdel {user} 2>/dev/null || true')
        a.run(f'useradd --system --no-create-home --no-user-group --gid 65534 --shell /usr/sbin/nologin {user}', root=True)
        uid = int(a.run(f'id -u {user}')['stdout'].strip())
        self.tun_probe_user,self.tun_probe_uid=user,uid
        # The application data parent is private to its service account.
        # Keep this disposable probe user's writable files under /run instead.
        self.download_directory = f'/run/{self.tag}-probe'
        if a.run(f'test -e {self.download_directory}', root=True, check=False)['code'] == 0:
            raise RuntimeError('benchmark probe directory already exists')
        journal.record('path', self.download_directory)
        a.run(f'install -d -m 700 {self.download_directory}; '
              f'chown {user}:65534 {self.download_directory}', root=True)
        comment = self.tag
        # Mark only this probe account. The root tunnel daemon's own outbound
        # connection to the same origin must not be fed back into its TUN.
        prefix = f"iptables -t mangle -p tcp -d {host}/32 --dport {origin[1]} -m owner --uid-owner {uid} -m comment --comment {comment}"
        add = prefix.replace('-t mangle ', '-t mangle -A OUTPUT ', 1) + f" -j MARK --set-mark {table}"
        delete = prefix.replace('-t mangle ', '-t mangle -D OUTPUT ', 1) + f" -j MARK --set-mark {table}"
        for command in (delete + " 2>/dev/null || true", f"ip rule del priority {priority} fwmark {table} lookup {table} 2>/dev/null || true",
                        f"ip route flush table {table}"):
            journal.record("cleanup_command", command)
        self.persist_resource(self.access[0][0]['id'], "route_table", str(table))
        a.run(f"ip route add {host}/32 dev {interface} table {table}; ip route add blackhole default table {table}; "
              f"ip rule add priority {priority} fwmark {table} lookup {table}; {add}", root=True)
        self.tun_route = (table, host, interface)
        route = a.run(f"ip route get {host} mark {table}", root=True)['stdout']
        if f"dev {interface}" not in route:
            return ProbeResult(False, "TUN policy route did not select the owned interface")
        command = f"runuser -u {user} -- curl --noproxy '*' -fsS --max-time 20 http://{host}:{origin[1]}/"
        result = a.run(command,
                       root=True, timeout=25, check=False)
        ok = result['code'] == 0 and result['stdout'].strip() == origin[2]
        self.http_flow = (a, command,
                          origin[0], origin[4], origin[2])
        self.observations = {"scope": "REAL_PAIR", "interface": interface,
                             "scoped_route": route.strip(), "payload_matched": ok}
        if self.artifact.get('tun_provider'):
            self.observations['tun_provider']=self.artifact['tun_provider']
            self.observations['transport']=self.artifact['transport']
        carrier=self.artifact.get('carrier_service')
        if ok and carrier and not self.carrier_verified:
            a.run(f'systemctl stop {shlex.quote(carrier)}.service',root=True)
            try:
                blocked=a.run(command.replace('--max-time 20','--max-time 5'),root=True,timeout=10,check=False)['code']!=0
            finally:
                a.run(f'systemctl start {shlex.quote(carrier)}.service',root=True)
                self._restore_scoped_routes()
            recovered=False
            until=time.monotonic()+self.profile.probe_timeout_s+20
            while time.monotonic()<until:
                answer=a.run(command,root=True,timeout=25,check=False)
                if answer['code']==0 and answer['stdout'].strip()==origin[2]:
                    recovered=True;break
                time.sleep(.3)
            self.observations['carrier_outage']={'service':carrier,'traffic_blocked':blocked,'recovered':recovered}
            self.carrier_verified=blocked and recovered
            ok=ok and self.carrier_verified
        return ProbeResult(ok, "remote unique HTTP payload through the actual TUN interface" if ok else 'TUN payload or its named carrier verification failed')

    def _probe_hajsaman_full(self):
        a, b = self.remotes
        art = self.artifact
        url = f"http://{art['full_origin']}:{art['full_origin_port']}/"
        command = f"curl --noproxy '' --socks5-hostname 127.0.0.1:{art['local_socks_port']} -fsS --max-time 5 {url}"
        self.http_flow = (a, command, b, art['full_directory'], art['full_payload'])
        result = a.run(command, root=True, timeout=8, check=False)
        payload_ok = result['code'] == 0 and result['stdout'].strip() == art['full_payload']
        counters = b.run(f"iptables -t nat -L POSTROUTING -nvx | grep -F {art['nat_comment']}", root=True)['stdout'].split()
        snat_packets = int(counters[0]) if counters else 0
        blocked, recovered, actions = self._carrier_outage(command, art['full_payload'])
        self.observations = {'scope': 'REAL_PAIR', 'stack': art['stack'], 'payload_matched': payload_ok,
                             'snat_packets': snat_packets, 'carrier_outage': {'traffic_blocked': blocked,
                                 'recovered': recovered, 'restoration_actions': actions},
                             'policy_route': a.run(f"ip route get {art['full_origin']} mark {art['policy_mark']}")['stdout'].strip()}
        ok = payload_ok and snat_packets > 0 and blocked and recovered
        return ProbeResult(ok, 'Xray mark, WG-over-SIT, scoped forwarding/SNAT and carrier outage verified'
                           if ok else 'full-stack payload, SNAT or carrier recovery check failed')

    def _carrier_outage(self, command, expected=None):
        remote = self.remotes[0]
        _, units = carrier_details(self.artifact)
        for name in units:
            remote.run(f"systemctl stop {shlex.quote(name.removesuffix('.service'))}.service", root=True)
        try:
            blocked = remote.run(command, root=True, timeout=10, check=False)['code'] != 0
        finally:
            actions = []
            # Restart the owned stages in dependency order. IPv6 addresses can
            # be removed on link-down and WG must bind its recreated underlay.
            actions = self._restart_components(self.artifact['components'])
            self._restore_scoped_routes()
        deadline = time.monotonic() + self.profile.probe_timeout_s + 20
        while time.monotonic() < deadline:
            response = remote.run(command, root=True, timeout=10, check=False)
            if response['code'] == 0 and (expected is None or response['stdout'].strip() == expected):
                return blocked, True, actions
            time.sleep(.5)
        return blocked, False, actions

    def _restore_scoped_routes(self):
        if self.artifact.get('policy_mark'):
            self.remotes[0].run(f"ip route replace {self.artifact['full_origin']}/32 dev "
                               f"{self.artifact['interface_name']} table {self.artifact['policy_mark']}", root=True)
        elif hasattr(self, 'tun_route'):
            table, host, interface = self.tun_route
            self.remotes[0].run(f'for i in $(seq 1 40); do ip link show {interface} >/dev/null 2>&1 && exit 0; sleep .5; done; exit 1', root=True, timeout=25)
            self.remotes[0].run(f'ip route replace {host}/32 dev {interface} table {table}', root=True)

    def _restart_components(self, components):
        actions = []
        def names(component, index):
            values = component.get('services_b' if index else 'services_a')
            if values:
                return list(dict.fromkeys(values))
            name = component.get('systemd_unit')
            if component.get('method') == 'WIREGUARD':
                name = 'wg-quick@' + component['interface_name']
            return [name] if name else []
        def restart(index, values):
            for name in values:
                self.remotes[index].run(f"systemctl restart {shlex.quote(name.removesuffix('.service'))}.service",
                                        root=True, timeout=self.profile.setup_timeout_s)
                actions.append(name)
        for component in components:
            a_names, b_names = names(component, 0), names(component, 1)
            if component.get('method') in {'SSH_TUN_L3', 'SSH_TAP_L2'}:
                # Recreate the SSH connection before configuring the new peer
                # TUN device. Restarting sshd last would delete that device again.
                restart(1, [name for name in b_names if not name.endswith('-if')])
                restart(0, a_names)
                restart(1, [name for name in b_names if name.endswith('-if')])
            else:
                restart(1, b_names)
                restart(0, a_names)
        return actions

    def metrics(self):
        snapshots = None
        if self.profile.throughput_seconds:
            from orchestrator.pair_metrics import (
                measure_http,
                measure_l3,
                measure_tun,
                measure_udp,
                resource_snapshot,
            )
            snapshots = [resource_snapshot(remote) for remote in self.remotes]
            if self.http_flow and hasattr(self,'tun_route'):
                self.measurements.update(measure_tun(self))
            elif self.http_flow:
                self.measurements.update(measure_http(self))
            elif self.udp_flow:
                self.measurements.update(measure_udp(self))
            elif self.artifact.get('tunnel_ip_a') and self.artifact.get('tunnel_ip_b'):
                self.measurements.update(measure_l3(self))
            else:
                raise RuntimeError('profile requires an actual throughput measurement path')
        if not self.http_flow and self.artifact.get('tunnel_ip_b'):
            # Use the same application request basis for L3 and stream tunnels.
            # Keep ICMP evidence separately; never mix SSH latency into the score.
            from plan_executor import executor as bodies
            self.measurements['icmp_metrics'] = dict(self.measurements)
            if not self.origins:
                self._origins(bodies, http_bind="::")
            origin = self.origins[1]
            target = ipaddress.ip_interface(self.artifact['tunnel_ip_b']).ip
            host = f'[{target}]' if target.version == 6 else str(target)
            command = f"curl --noproxy '*' -fsS --max-time 15 http://{host}:{origin[1]}/"
            self.http_flow = (self.remotes[0], command, origin[0], origin[4], origin[2])
        if self.http_flow:
            from orchestrator.pair_metrics import measure_http_latency
            self.measurements.update(measure_http_latency(self))
        elif self.udp_flow:
            self.measurements['rtt_basis'] = 'udp_echo'
        if self.profile.restart_test:
            baseline_metrics = dict(self.measurements)
            baseline_evidence = self.observations
            started = time.monotonic()
            self._restart_components(self.artifact.get('components') or [self.artifact])
            if self.artifact.get('components') and self.artifact.get('full_origin'):
                self.remotes[0].run(f'systemctl restart {self.tag}-haj-xray.service', root=True)
            self._restore_scoped_routes()
            recovered = False
            deadline = time.monotonic() + self.profile.probe_timeout_s + 20
            while time.monotonic() < deadline:
                if self.http_flow:
                    remote, command, _, _, nonce = self.http_flow
                    response = remote.run(command, root=True, check=False)
                    recovered = response['code'] == 0 and response['stdout'].strip() == nonce
                else:
                    recovered = self.probe().ok
                if recovered:
                    break
                time.sleep(.5)
            recovery_evidence = self.observations
            self.measurements = baseline_metrics
            self.observations = baseline_evidence
            self.measurements.update(reconnect_s=round(time.monotonic() - started, 3), recovery_ok=recovered,
                                     recovery_evidence=recovery_evidence)
            if not recovered:
                raise RuntimeError('owned service restart did not recover real traffic')
            self._check_management_routes()
        if snapshots:
            from orchestrator.pair_metrics import resource_snapshot, resource_usage
            resources = [resource_usage(before, resource_snapshot(remote))
                         for before, remote in zip(snapshots, self.remotes)]
            self.measurements.update(cpu_pct=max(row['cpu_pct'] for row in resources),
                                     ram_mb=max(row['ram_mb'] for row in resources),
                                     resource_evidence={'scope': 'whole_node', 'samples': resources})
        return self.failure_metrics()

    def failure_metrics(self):
        """Read existing evidence without triggering additional network tests."""
        return {**self.measurements, "evidence": self.observations}

    def rollback(self):
        from plan_executor import executor as bodies
        errors = []
        for remote in self.remotes:
            remote.deadline = None  # cleanup has its own timeout and is always attempted.
            remote.observer = None
            remote.cancelled = None
        try:
            if self.artifact and len(self.remotes) == 2:
                try:
                    bodies.rollback_artifact(*self.remotes, self.artifact)
                except Exception as e:  # noqa: BLE001 - attempt every independent cleanup step
                    errors.append("primary teardown: " + str(e))
            for remote, port, payload, service, directory, udp_port in self.origins:
                try:
                    stop_owned_transient(remote,service)
                    remote.run(f"rm -rf {shlex.quote(directory)}",root=True,timeout=20)
                except Exception as e:  # noqa: BLE001 - attempt every independent cleanup step
                    errors.append(str(e))
            for remote, service in self.extra_services:
                try:
                    stop_owned_transient(remote,service)
                except Exception as e:  # noqa: BLE001 - attempt every independent cleanup step
                    errors.append(str(e))
            if self.artifact:
                for index, remote in enumerate(self.remotes):
                    for name in self.artifact.get("services_a" if index == 0 else "services_b", []):
                        if remote.run(f"systemctl is-active --quiet {shlex.quote(name)}.service", check=False)["code"] == 0:
                            errors.append("owned service still active: " + name)
            for journal in self.journals:
                try:
                    journal.cleanup()
                except Exception as e:  # noqa: BLE001 - attempt every independent cleanup step
                    errors.append(str(e))
            try:
                self._check_management_routes()
            except Exception as e:  # noqa: BLE001 - attempt every independent cleanup step
                errors.append(str(e))
        finally:
            for remote in self.remotes:
                remote.close()
            for lock in reversed(self.acquired):
                lock.release()
            self.acquired.clear()
        if errors:
            raise RuntimeError("; ".join(errors)[:180])
