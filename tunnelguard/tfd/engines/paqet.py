"""TunnelGuard — Paqet raw-packet KCP tunnel engine adapter.

paqet (github.com/hanselime/paqet — DashSaman fork) tunnels traffic inside
RAW TCP packets: it crafts outbound packets with gopacket and captures
inbound ones with pcap, bypassing the kernel TCP stack and its conntrack.
On top it runs KCP (reliable-UDP-style ARQ over the raw packets) + smux,
encrypted with a shared key. The client exposes a local SOCKS5 ingress and
optional static port-forwards; the server forwards egress traffic to the
internet (SNAT-style, via the normal stack).

TunnelGuard manages ONE paqet endpoint per tunnel record:
  role=client  (Iran side — the useful monitoring side: real SOCKS5 probes)
  role=server  (Foreign side — liveness monitoring only)

Config keys (tunnel.config JSON):
  role              client|server            (default client)
  binary_path       paqet binary             (default /usr/local/bin/paqet)
  conf_path         where the YAML lands     (default <DATA_DIR>/paqet/<name>.yaml)
  server_addr       host:port of the paqet server   (client role, required)
  listen_addr       server bind, e.g. ":9999"       (server role, required)
  socks_listen      client SOCKS5 bind "127.0.0.1:1080"
  socks_user/socks_pass   optional SOCKS5 auth
  forward           list of {listen,target,protocol} static port-forwards
  interface         capture interface (eth0)         (required both roles)
  local_ipv4        "ip:port" source addr, client port 0, server must match listen
  router_mac        gateway MAC for raw framing      (required both roles)
  local_ipv6        optional IPv6 equivalent
  kcp_key           shared secret (required, must match on both sides)
  kcp_block         aes|aes-128|salsa20|...  (default aes; none/null = warned)
  kcp_mode          normal|fast|fast2|fast3|manual (default fast)
  kcp_conn          1..256 multiplexed connections (default 1)
  tcp_flags         local/remote flag cycle list, default ["PA"]
  iptables_setup    server: apply NOTRACK + RST-drop rules on up (default true)
  standalone        run binary directly (no systemd) — default true
  probe_target/probe_port   through-tunnel probe target (default 1.1.1.1:443)

Honest engineering notes:
- Raw sockets need CAP_NET_RAW (root). The adapter checks that up front and
  says exactly what is missing instead of failing later at runtime.
- The kernel still SEES the raw packets; the README-mandated iptables rules
  (NOTRACK on the server port + drop of kernel-generated RSTs) are rendered
  and applied on up() when iptables_setup is on — without them NAT devices
  corrupt the flow.
- This is a SOCKS5/port-forward tunnel: the kernel cannot route the VIP
  through it, so like Hedioum-without-TUN it is probed for health but never
  promoted to the ACTIVE VIP carrier by the FSM (routing_capable=False).
"""
from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import time

from .base import EngineAdapter, AdapterError
from .. import config as appconfig

DEFAULT_BINARY = "/usr/local/bin/paqet"
_popen = subprocess.Popen  # patch point for tests

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_WEAK_BLOCKS = {"none", "null"}
_STD_PORTS = {80, 443, 22, 53}


class PaqetAdapter(EngineAdapter):
    name = "paqet"

    # proxy tunnel: SOCKS5 / port-forward ingress, not kernel-routable
    @property
    def routing_capable(self) -> bool:
        return False

    # ------------------------------------------------------------- identity
    @property
    def role(self) -> str:
        return "server" if str(self.cfg.get("role", "client")).lower() \
            .startswith("serv") else "client"

    @property
    def display_name(self) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "_",
                      self.t.get("name") or f"tg{self.t.get('id', 0)}")

    @property
    def binary(self) -> str:
        b = self.cfg.get("binary_path") or DEFAULT_BINARY
        if not os.path.exists(b):
            w = self._which("paqet")
            if w:
                b = w
        return b

    @property
    def conf_path(self) -> str:
        if self.cfg.get("conf_path"):
            return str(self.cfg["conf_path"])
        return f"{appconfig.DATA_DIR}/paqet/{self.display_name}.yaml"

    @property
    def workdir(self) -> str:
        return f"{appconfig.DATA_DIR}/paqet/{self.display_name}"

    @property
    def socks_hostport(self) -> tuple[str, int]:
        raw = self.cfg.get("socks_listen") or "127.0.0.1:1080"
        host, _, port = raw.rpartition(":")
        return (host or "127.0.0.1", int(port or 1080))

    @property
    def server_port(self) -> int:
        raw = str(self.cfg.get("listen_addr") or ":9999")
        _, _, port = raw.rpartition(":")
        return int(port or 9999)

    # --------------------------------------------------------------- render
    def _yaml(self) -> str:
        c = self.cfg
        kcp: dict = {
            "mode": c.get("kcp_mode") or "fast",
            "block": c.get("kcp_block") or "aes",
        }
        if c.get("kcp_key"):
            kcp["key"] = str(c["kcp_key"])
        for src, dst in (("kcp_mtu", "mtu"), ("kcp_sndwnd", "sndwnd"),
                         ("kcp_rcvwnd", "rcvwnd"), ("kcp_nodelay", "nodelay"),
                         ("kcp_interval", "interval"), ("kcp_resend", "resend"),
                         ("kcp_nocongestion", "nocongestion")):
            if c.get(src) is not None and c.get(src) != "":
                kcp[dst] = int(c[src])
        net: dict = {
            "interface": c.get("interface") or "",
            "ipv4": {"addr": c.get("local_ipv4") or "",
                     "router_mac": c.get("router_mac") or ""},
        }
        if c.get("local_ipv6"):
            net["ipv6"] = {"addr": c["local_ipv6"],
                           "router_mac": c.get("router_mac") or ""}
        flags = c.get("tcp_flags") or ["PA"]
        if isinstance(flags, str):
            flags = [f.strip() for f in flags.split(",") if f.strip()]
        net["tcp"] = {"local_flag": flags, "remote_flag": flags}
        doc: dict = {"role": self.role,
                     "log": {"level": c.get("log_level") or "info"},
                     "network": net,
                     "transport": {"protocol": "kcp",
                                   "conn": int(c.get("kcp_conn") or 1),
                                   "kcp": kcp}}
        if self.role == "client":
            doc["server"] = {"addr": c.get("server_addr") or ""}
            sh, sp = self.socks_hostport
            sock = {"listen": f"{sh}:{sp}"}
            if c.get("socks_user"):
                sock["username"] = str(c["socks_user"])
                sock["password"] = str(c.get("socks_pass") or "")
            doc["socks5"] = [sock]
            fwds = c.get("forward") or []
            if isinstance(fwds, dict):
                fwds = [fwds]
            rendered = []
            for f in fwds:
                if isinstance(f, dict) and f.get("listen") and f.get("target"):
                    rendered.append({"listen": f["listen"],
                                     "target": f["target"],
                                     "protocol": f.get("protocol") or "tcp"})
            if rendered:
                doc["forward"] = rendered
        else:
            doc["listen"] = {"addr": c.get("listen_addr") or ":9999"}
        return _dump_yaml(doc)

    def _iptables_script(self) -> str:
        port = self.server_port
        return (
            "#!/bin/sh\n"
            "# paqet server kernel-bypass rules (see paqet README — Critical\n"
            "# Firewall Configuration). Idempotent; rendered by TunnelGuard.\n"
            f"iptables -t raw -C PREROUTING -p tcp --dport {port} -j NOTRACK "
            "2>/dev/null || iptables -t raw -A PREROUTING -p tcp "
            f"--dport {port} -j NOTRACK\n"
            f"iptables -t raw -C OUTPUT -p tcp --sport {port} -j NOTRACK "
            "2>/dev/null || iptables -t raw -A OUTPUT -p tcp "
            f"--sport {port} -j NOTRACK\n"
            f"iptables -t mangle -C OUTPUT -p tcp --sport {port} "
            "--tcp-flags RST RST -j DROP 2>/dev/null || "
            f"iptables -t mangle -A OUTPUT -p tcp --sport {port} "
            "--tcp-flags RST RST -j DROP\n"
        )

    def render(self) -> dict[str, str]:
        out = {self.conf_path: self._yaml()}
        if self.role == "server" and self.cfg.get("iptables_setup", True):
            out[f"{self.workdir}/paqet-firewall.sh"] = self._iptables_script()
        return out

    def _systemd_unit(self) -> str:
        return (
            "[Unit]\n"
            f"Description=paqet ({self.role}) managed by TunnelGuard\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\nExecStart="
            f"{self.binary} run -c {self.conf_path}\n"
            "Restart=on-failure\nRestartSec=3\n"
            f"WorkingDirectory={self.workdir}\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )

    # ------------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        p: list[str] = []
        c = self.cfg
        if not os.path.exists(self.binary):
            p.append("paqet binary not found — install it first "
                     "(scripts/install_paqet.sh builds from the repo or "
                     "grab a release binary)")
        # raw sockets need CAP_NET_RAW; on Linux effectively root
        if os.name == "posix" and (os.geteuid() != 0):
            p.append("paqet needs raw sockets: run TunnelGuard with root "
                     "privileges (CAP_NET_RAW), otherwise pcap open fails")
        if not c.get("interface"):
            p.append("network.interface missing (capture interface, e.g. eth0)")
        if not _MAC_RE.match(c.get("router_mac") or ""):
            p.append("network.router_mac missing/invalid (gateway MAC for raw "
                     "framing — `ip neigh show dev <iface>`)")
        if not c.get("local_ipv4"):
            p.append("network.ipv4.addr missing (local 'ip:port', client uses "
                     "port 0)")
        if not c.get("kcp_key"):
            p.append("transport.kcp.key missing (shared secret, must match "
                     "on client and server)")
        if (c.get("kcp_block") or "").lower() in _WEAK_BLOCKS:
            p.append("kcp.block is 'none'/'null' — authentication DISABLED, "
                     "anyone who knows the IP:port can connect (paqet README "
                     "warning)")
        if self.role == "client":
            if not c.get("server_addr"):
                p.append("server.addr missing (paqet server host:port)")
            sh, sp = self.socks_hostport
            if self._port_in_use(sp, expect_own=True):
                p.append(f"SOCKS5 listen port {sp} already in use by another "
                         "process")
        else:
            if not c.get("listen_addr"):
                p.append("listen.addr missing (server bind, e.g. ':9999')")
            if self.server_port in _STD_PORTS:
                p.append(f"listen port {self.server_port} is a standard port "
                         "— paqet README forbids 80/443/etc (iptables rules "
                         "would hit unrelated traffic)")
            if c.get("iptables_setup", True) and self._iptables_missing():
                p.append("server NOTRACK/RST-drop iptables rules not present "
                         "— they are applied on up() when running as root")
        return p

    def _port_in_use(self, port: int, expect_own: bool = False) -> bool:
        cp = self.exec(["ss", "-tln"], timeout=10)
        if cp.returncode != 0:
            return False
        for line in cp.stdout.splitlines():
            cols = line.split()
            if len(cols) >= 4 and cols[3].endswith(f":{port}"):
                if expect_own and self._pid_alive():
                    continue
                return True
        return False

    def _iptables_missing(self) -> bool:
        cp = self.exec(["iptables-save", "-t", "raw"], timeout=10)
        if cp.returncode != 0:
            return True
        want = f"--dport {self.server_port} -j NOTRACK"
        return want not in cp.stdout

    # ------------------------------------------------------------------ up
    def up(self) -> list[str]:
        if not os.path.exists(self.binary):
            raise AdapterError(f"paqet binary missing at {self.binary}")
        executed: list[str] = []
        for path, content in self.render().items():
            self.write_artifact(path, content, mode=0o600)
            executed.append(f"write {path}")
        os.makedirs(self.workdir, exist_ok=True)
        if self.role == "server" and self.cfg.get("iptables_setup", True):
            cp = self.exec(["sh", f"{self.workdir}/paqet-firewall.sh"],
                           timeout=20)
            executed.append(f"iptables NOTRACK/RST rules "
                            f"(rc={cp.returncode})")
        if self.cfg.get("standalone", True):
            executed += self._up_standalone()
        else:
            unit = f"{self.workdir}/paqet-{self.display_name}.service"
            self.write_artifact(unit, self._systemd_unit(), mode=0o644)
            svc = f"paqet-{self.display_name}"
            executed += [f"write {unit} (copy to /etc/systemd/system/ and "
                         f"systemctl enable --now {svc})"]
        self._wait_ready()
        return executed

    def _up_standalone(self) -> list[str]:
        self._stop_standalone()
        logf = open(f"{self.workdir}/paqet.log", "ab")
        proc = _popen([self.binary, "run", "-c", self.conf_path],
                      cwd=self.workdir, stdout=logf,
                      stderr=subprocess.STDOUT, start_new_session=True)
        with open(f"{self.workdir}/paqet.pid", "w") as f:
            f.write(str(proc.pid))
        return [f"standalone start pid={proc.pid} role={self.role}"]

    def _wait_ready(self) -> None:
        """Client: wait until SOCKS5 ingress accepts. Server: wait until the
        raw listener process is alive (raw sockets never accept())."""
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.role == "client" and self._socks_alive():
                return
            if self.role == "server" and self._pid_alive():
                return
            time.sleep(0.5)
        if self.role == "client":
            raise AdapterError(
                f"SOCKS5 ingress on {self.cfg.get('socks_listen')} did not "
                "come up within 15s — check "
                f"{self.workdir}/paqet.log")
        if not self._pid_alive():
            raise AdapterError(
                f"paqet server process died immediately — check "
                f"{self.workdir}/paqet.log (root? interface? router_mac?)")

    # ---------------------------------------------------------------- down
    def _stop_standalone(self) -> list[str]:
        done = []
        try:
            with open(f"{self.workdir}/paqet.pid") as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            done.append(f"killed standalone pid={pid}")
        except (OSError, ValueError):
            pass
        try:
            os.remove(f"{self.workdir}/paqet.pid")
        except OSError:
            pass
        return done

    def down(self) -> list[str]:
        executed = self._stop_standalone()
        if not executed:
            executed.append("no standalone process found (systemd-managed "
                            "installs: systemctl stop paqet-"
                            f"{self.display_name})")
        return executed

    # -------------------------------------------------------------- status
    def _socks_alive(self) -> bool:
        host, port = self.socks_hostport
        try:
            with socket.create_connection((host, port), timeout=1.5):
                return True
        except OSError:
            return False

    def _pid_alive(self) -> bool:
        try:
            with open(f"{self.workdir}/paqet.pid") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False

    def status(self) -> dict:
        proc_ok = self._pid_alive()
        if self.role == "client":
            socks_ok = self._socks_alive()
            up = bool(proc_ok and socks_ok)
            detail = ("standalone client: SOCKS5 " +
                      (f"{self.socks_hostport[1]} accepting"
                       if socks_ok else "NOT accepting"))
        else:
            up = proc_ok
            detail = ("standalone server process alive"
                      if proc_ok else "server process not running")
        extra = {"role": self.role,
                 "server_addr": self.cfg.get("server_addr")
                 or self.cfg.get("listen_addr"),
                 "kcp_block": self.cfg.get("kcp_block") or "aes"}
        return {"up": up, "detail": detail, "extra": extra}

    # --------------------------------------------------------------- probe
    def _probe_cycle(self) -> dict:
        from .. import probes
        if self.role == "client":
            target = self.cfg.get("probe_target") or "1.1.1.1"
            port = int(self.cfg.get("probe_port") or 443)
            s = self._settings()
            return probes.socks5_cycle(
                self.socks_hostport[1], target, port,
                count=max(2, int(s.get("probe_count", 5)) // 2),
                timeout_s=float(s.get("probe_timeout_s", 2)) + 2.0)
        # server role: the egress end. Honest liveness probe only — the
        # through-tunnel path is measured by the client side record.
        alive = self._pid_alive()
        return {"rtt_ms": None, "loss_pct": 0.0 if alive else 100.0,
                "jitter_ms": None, "ok": alive, "method": "liveness",
                "detail": None if alive else "paqet server process dead"}

    def receipt(self) -> dict:
        """Client role: real HTTP GET through the raw-packet tunnel — proves
        KCP+smux end-to-end and reports the foreign exit IP."""
        from .. import probes
        if self.role != "client":
            return {"exit_ip": None, "through_tunnel": False,
                    "attempts": 0, "note": "receipt only exists client-side"}
        providers = (("api.ipify.org", "/"), ("icanhazip.com", "/"),
                     ("ifconfig.me", "/ip"))
        attempts = 0
        for _round in range(3):
            for host, path in providers:
                attempts += 1
                body = probes.socks5_http_get(self.socks_hostport[1],
                                              host, path)
                if body and len(body) <= 64 and not body.startswith("<"):
                    return {"exit_ip": body.strip(), "through_tunnel": True,
                            "attempts": attempts, "provider": host}
            time.sleep(1.0)
        return {"exit_ip": None, "through_tunnel": False, "attempts": attempts}


# --------------------------------------------------------------------- yaml
def _dump_yaml(doc: dict) -> str:
    """Minimal YAML emitter for the paqet config subset (no deps)."""
    lines: list[str] = []

    def scalar(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        if ": " in s or re.match(r"^[-:?$@`|<>=!%&*{[\]#]", s) \
                or s.strip() == "" or s != s.strip():
            return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
        return s

    def block(prefix: str, obj, indent: int):
        pad = "  " * indent
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    block(prefix + k + ".", v, indent + 1)
                else:
                    lines.append(f"{pad}{k}: {scalar(v)}")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    first = True
                    for k, v in item.items():
                        lead = "- " if first else "  "
                        if isinstance(v, (dict, list)):
                            lines.append(f"{pad}{lead}{k}:")
                            block("", v, indent + 2)
                        else:
                            lines.append(f"{pad}{lead}{k}: {scalar(v)}")
                        first = False
                else:
                    lines.append(f"{pad}- {scalar(item)}")

    block("", doc, 0)
    return "\n".join(lines) + "\n"
