"""Record unique run-owned physical resources before remote mutation."""
import re
import shlex


class RemoteJournal:
    def __init__(self, remote, run_id, item_id, node_id, persist):
        self.remote, self.node_id, self.persist = remote, node_id, persist
        self.marker = f"{run_id}-{item_id}"
        self.namespace = f"{run_id}-"
        self.units, self.paths, self.interfaces, self.auth_markers = set(), set(), set(), set()
        self.cleanup_commands = set()
        self.firewall_rules = set()

    def record(self, kind, key):
        bucket = {"service": self.units, "path": self.paths, "interface": self.interfaces,
                  "auth_marker": self.auth_markers, "cleanup_command": self.cleanup_commands,
                  "firewall_rule": self.firewall_rules}[kind]
        if key in bucket:
            return
        self.persist(self.node_id, kind, key)
        bucket.add(key)
        if kind == 'interface':
            from orchestrator.host_reservations import reserve
            reserve(self.remote, 'interfaces', key)

    def observe(self, command):
        # A deployment can fail midway; persist its resources before executing.
        for family, peer in re.findall(r"ip (-6 )?rule add priority 219 to ([0-9a-fA-F:./]+) lookup main", command):
            self.record('cleanup_command', f'ip {family}rule del priority 219 to {peer} lookup main 2>/dev/null || true')
        for name in re.findall(r"ip (?:-6 )?(?:link|tunnel) (?:add|del) ([A-Za-z0-9_.-]+)", command):
            self.claim_interface(name)
        for path in re.findall(r"/etc/wireguard/(nwg[A-Za-z0-9]+)\.conf", command):
            if not path.startswith(f"nwg{int(self.marker.split('-')[0]):x}"):
                raise RuntimeError("unowned WireGuard configuration")
            full = f"/etc/wireguard/{path}.conf"
            if full not in self.paths:
                if self.remote.run(f"test -e {full}", check=False)['code'] == 0:
                    raise RuntimeError("deployment WireGuard configuration already exists")
                if self.remote.run(f"ip link show {path}", check=False)['code'] == 0:
                    raise RuntimeError("deployment interface already exists: " + path)
                self.record("path", full)
                self.record("interface", path)
                self.record("service", f"wg-quick@{path}")
        for unit in re.findall(r"(?:/etc/systemd/system/|--unit=)([A-Za-z0-9@_.-]+)", command):
            unit = unit.removesuffix(".service")
            if self.namespace in unit:
                if unit not in self.units and self.remote.run(
                        f'test -e /etc/systemd/system/{shlex.quote(unit)}.service', check=False)['code'] == 0:
                    raise RuntimeError('deployment service already exists: ' + unit)
                self.record("service", unit)
        for path in re.findall(r"/(?:etc/netauto|etc/swanctl/conf.d|var/lib/tunnelpannel/bench|usr/local/share/ca-certificates)/[^\s'\"<>;&]+", command):
            if self.namespace in path:
                self.record("path", path)
                if path.startswith('/etc/swanctl/conf.d/'):
                    connection = re.match(r'(netauto-\d+-\d+)', path.rsplit('/', 1)[-1])
                    if connection:
                        owner = connection[1]
                        self.record('cleanup_command', 'swanctl --load-all --noprompt >/dev/null 2>&1; '
                                    f'swanctl --terminate --ike {owner} --timeout 5 2>/dev/null || true')
        for marker in re.findall(r"netauto:[A-Za-z0-9_.-]+", command):
            if self.marker in marker:
                self.record("auth_marker", marker)
        for marker in re.findall(r'NETAUTO_L2TP_\d+_\d+', command):
            if marker.startswith('NETAUTO_L2TP_' + self.namespace.removesuffix('-') + '_'):
                self.record('cleanup_command', f"sed -i '/{marker}/d' /etc/ppp/chap-secrets")

    def claim_interface(self, name):
        if name in self.interfaces:
            return
        if name in getattr(self.remote, 'reserved_interfaces', set()):
            raise RuntimeError('deployment interface already reserved: ' + name)
        if self.remote.run(f"ip link show {shlex.quote(name)}", check=False)["code"] == 0:
            raise RuntimeError("deployment interface already exists: " + name)
        self.record('interface', name)

    def cleanup(self):
        r = self.remote
        for name in sorted(self.units, reverse=True):
            unit = shlex.quote(name + ".service")
            r.run(f"systemctl stop --no-block {unit} 2>/dev/null || true; "
                  f"systemctl kill --kill-whom=all --signal=KILL {unit} 2>/dev/null || true; "
                  f"systemctl disable {unit} 2>/dev/null || true; "
                  f"rm -f /etc/systemd/system/{unit}", root=True, timeout=25)
            if r.run(f"systemctl is-active --quiet {unit}", check=False)["code"] == 0:
                raise RuntimeError("owned service survived cleanup: " + name)
        for name in self.interfaces:
            value = shlex.quote(name)
            r.run(f"ip link del {value} 2>/dev/null || true", root=True)
            if r.run(f"ip link show {value}", check=False)["code"] == 0:
                raise RuntimeError("owned interface survived cleanup: " + name)
        reservation_books = {path for path in self.paths
                             if path.startswith('/var/lib/tunnelpannel-engine-reservations/')}
        for path in sorted(self.paths - reservation_books, key=len, reverse=True):
            value = shlex.quote(path)
            r.run(f"rm -rf -- {value}", root=True)
            r.run(f"test ! -e {value}", root=True)
        for marker in self.auth_markers:
            value = re.escape(marker)
            r.run(f"sed -i '/{value}/d' /root/.ssh/authorized_keys", root=True)
        for command in self.cleanup_commands:
            r.run(command, root=True, timeout=20)
        for key in self.firewall_rules:
            tool, marker = key.split('|', 1)
            if tool not in {'iptables', 'ip6tables'} or not re.fullmatch(r'tp-\d+-\d+-[0-9a-f]{12}', marker):
                raise RuntimeError('invalid owned firewall identity')
            current = r.run(tool + '-save -t filter', root=True, timeout=20)['stdout']
            if marker in current:
                raise RuntimeError('owned firewall rule survived cleanup')
        if self.units:
            r.run("systemctl daemon-reload", root=True)
        # Do not make stopped-member allocations reusable after partial cleanup.
        for path in reservation_books:
            value = shlex.quote(path)
            r.run(f'rm -f -- {value}', root=True)
            r.run(f'test ! -e {value}', root=True)
