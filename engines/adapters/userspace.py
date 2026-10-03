"""Userspace engine adapters (P5 U2) — one adapter per ENGINE, profile table inside.

Command shapes mirror the proven Gen2 harness (deploy/engine/mtf_userspace.py)
and Gen1 executor argument construction; process lifetime uses pidfiles under
/run/tunnelpannel and configs under /etc/tunnelpannel. Probes are data-plane
truth gates per §5: SOCKS CONNECT, HTTP via proxy, TCP/UDP through the
forwarded service, ping through TUN — never "process alive".
"""
from __future__ import annotations

import dataclasses
from typing import Callable

from engines.adapters import EngineAdapter, PlanAction, ProbeResult, register_adapter
from engines.adapters.kernel import CommandPlanAdapter

RUN_DIR = "/run/tunnelpannel"
CONF_DIR = "/etc/tunnelpannel"
ECHO_PORT = 14080                    # local echo/HTTP target used by probes


@dataclasses.dataclass
class ProfileSpec:
    profile_id: str
    scheme: str                       # transport scheme (for arg builders)
    server_args: Callable[[dict], list[str]]      # (params) -> argv
    client_args: Callable[[dict], list[str]] | None = None
    config_renderer: Callable[[dict, "ProfileSpec"], str] | None = None
    config_ext: str = "conf"
    probe: str = "socks5"             # socks5|http|tcp|udp|tun|tap
    secrets: tuple[str, ...] = ()     # param keys whose values get redacted
    notes: str = ""


def _ports(p: dict) -> tuple[int, int]:
    return int(p.get("server_port", 14101)), int(p.get("client_port", 14102))


_FORWARD_SCHEMES = ("tcp", "udp", "kcp")     # port-forward styles (server relays to ECHO)


def _gost_server(p: dict) -> list[str]:
    ps, _ = _ports(p)
    scheme = p["scheme"]
    if scheme in _FORWARD_SCHEMES:            # e.g. -L tcp://PS/127.0.0.1:ECHO (harness shape)
        return ["gost", "-L", f"{scheme}://127.0.0.1:{ps}/127.0.0.1:{ECHO_PORT}"]
    return ["gost", "-L", f"{scheme}://127.0.0.1:{ps}"]


def _gost_client(p: dict) -> list[str] | None:
    ps, pc = _ports(p)
    scheme = p["scheme"]
    if scheme in ("tcp", "udp"):              # pure forward: probe goes via server port
        return None
    if scheme == "kcp":                       # tcp client riding kcp carrier
        return ["gost", "-L", f"tcp://127.0.0.1:{pc}", "-F", f"kcp://127.0.0.1:{ps}"]
    return ["gost", "-L", f"socks5://127.0.0.1:{pc}", "-F", f"{scheme}://127.0.0.1:{ps}"]


def _no_client(_p: dict) -> None:
    return None


class UserspaceAdapter(CommandPlanAdapter):
    """Generic userspace lifecycle; subclasses provide PROFILES + BINARY."""

    BINARY = ""
    PROFILES: dict[str, ProfileSpec] = {}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        pid = self.params.get("profile", "default")
        if pid not in self.PROFILES:
            raise KeyError(f"engine {self.engine_id}: unknown profile {pid!r} "
                           f"(have: {sorted(self.PROFILES)})")
        self.spec = self.PROFILES[pid]

    # naming helpers
    @property
    def _tag(self) -> str:
        return f"{self.engine_id}-{self.spec.profile_id}"

    @property
    def _pidfile(self) -> str:
        return f"{RUN_DIR}/{self._tag}.pid"

    @property
    def _pidfile_c(self) -> str:
        return f"{RUN_DIR}/{self._tag}-c.pid"

    @property
    def _conf(self) -> str:
        return f"{CONF_DIR}/{self._tag}.{self.spec.config_ext}"

    # ── EngineAdapter ──
    def detect(self) -> bool:
        rc, _ = self.executor.run(f"command -v {self.BINARY}")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run(f"{self.BINARY} --version 2>&1 | head -1; "
                                   f"ls {RUN_DIR}/{self._tag}* 2>/dev/null")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append(f"{self.BINARY} binary missing (see engines.packages)")
        if not self.params.get("server_port") and self.spec.server_args is not None:
            problems.append("no server_port allocated")
        if self.spec.client_args is not None and not self.params.get("client_port"):
            problems.append("no client_port allocated")
        return problems

    def commands(self) -> list[tuple[str, str]]:
        p = dict(self.params)
        p["scheme"] = self.spec.scheme
        cmds: list[tuple[str, str]] = [
            ("dirs", f"mkdir -p {RUN_DIR} {CONF_DIR}"),
        ]
        if self.spec.config_renderer is not None:
            body = self.spec.config_renderer(p, self.spec)
            cmds.append(("write config",
                         f"cat > {self._conf} <<'TPCONF'\n{body}\nTPCONF"))
        srv = self.spec.server_args(p)
        cmds.append(("start server",
                     f"nohup {' '.join(srv)} >{RUN_DIR}/{self._tag}.log 2>&1 & echo $! > {self._pidfile}"))
        cli = self.spec.client_args
        if cli is not None:
            argv = cli(p)
            if argv:
                cmds.append(("start client",
                             f"nohup {' '.join(argv)} >{RUN_DIR}/{self._tag}-c.log 2>&1 & "
                             f"echo $! > {self._pidfile_c}"))
        return cmds

    def rollback_commands(self) -> list[tuple[str, str]]:
        cmds = [
            ("stop client", f"kill $(cat {self._pidfile_c} 2>/dev/null) 2>/dev/null; rm -f {self._pidfile_c}"),
            ("stop server", f"kill $(cat {self._pidfile} 2>/dev/null) 2>/dev/null; rm -f {self._pidfile}"),
        ]
        if self.spec.config_renderer is not None:
            cmds.append(("remove config", f"rm -f {self._conf}"))
        return cmds

    # ── truth-gate probes ──
    def probe_commands(self) -> list[str]:
        _, pc = _ports(self.params)
        kind = self.spec.probe
        ps, _ = _ports(self.params)
        if kind == "socks5":
            return [f"curl -s -o /dev/null -w '%{{http_code}}' --socks5-hostname 127.0.0.1:{pc} "
                    f"--max-time 6 http://127.0.0.1:{ECHO_PORT}/"]
        if kind == "http":
            return [f"curl -s -o /dev/null -w '%{{http_code}}' -x http://127.0.0.1:{pc} "
                    f"--max-time 6 http://127.0.0.1:{ECHO_PORT}/"]
        if kind == "tcp":
            target = self.params.get("probe_port", pc or ps)
            return [f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 6 http://127.0.0.1:{target}/"]
        if kind == "udp":
            target = self.params.get("probe_port", ps)
            return [f"echo tp-probe | timeout 6 nc -u -w 3 127.0.0.1 {target} | grep -q tp-probe"]
        if kind in ("tun", "tap"):
            return [f"ping -c 3 -W 2 -I {self.params['interface']} {self.params['probe_target']}"]
        raise ValueError(f"unknown probe kind {kind}")

    def probe(self) -> ProbeResult:
        cmds = self.probe_commands()
        for cmd in cmds:
            rc, out = self.executor.run(cmd, timeout=12)
            ok = (rc == 0) and ("200" in out or "tp-probe" in out or "ttl=" in out)
            if not ok:
                return ProbeResult(ok=False,
                                   evidence=f"{self.spec.probe} probe failed: {cmd[:90]} -> rc={rc} {out[-120:]}")
        return ProbeResult(ok=True,
                           evidence=f"{self.spec.probe} data-plane verified via {cmds[0][:70]}")

    # ── secret redaction (§8) ──
    def redacted_params(self) -> dict:
        out = dict(self.params)
        for key in self.spec.secrets:
            if key in out:
                out[key] = "***REDACTED***"
        return out


# ═══════════════ engine families ═══════════════

def _gost_probe(profile_id: str) -> str:
    if profile_id in ("tcp_forward", "kcp_forward", "remote_tcp"):
        return "tcp"
    if profile_id in ("udp_forward", "remote_udp"):
        return "udp"
    if profile_id == "tun":
        return "tun"
    if profile_id == "tap":
        return "tap"
    return "socks5"


@register_adapter
class GostAdapter(UserspaceAdapter):
    engine_id = "gost"
    BINARY = "gost"
    PROFILES = {
        pid: ProfileSpec(pid, scheme, _gost_server, _gost_client,
                         probe=_gost_probe(pid), secrets=("password",))
        for pid, scheme in [
            ("socks5", "socks5"), ("http", "http"), ("ws", "ws"), ("grpc", "grpc"),
            ("http2", "h2"), ("quic", "quic"), ("kcp_forward", "kcp"),
            ("socks5_kcp", "socks5+kcp"), ("remote_tcp", "rtcp"), ("remote_udp", "rudp"),
            ("ssh", "ssh"), ("tap", "tap"), ("tun", "tun"),
            ("tcp_forward", "tcp"), ("udp_forward", "udp"),
        ]
    }


def _xray_config(p: dict, spec: ProfileSpec) -> str:
    ps, pc = _ports(p)
    uid = p.get("user_id", "00000000-0000-0000-0000-000000000001")
    transport = {"ws": "ws", "grpc": "grpc"}.get(spec.profile_id.replace("vless_", ""), "tcp")
    import json
    server = {
        "inbounds": [{"port": ps, "protocol": "vless",
                      "settings": {"clients": [{"id": uid}]},
                      "streamSettings": {"network": transport}}],
        "outbounds": [{"protocol": "freedom"}],
    }
    client = {
        "inbounds": [{"port": pc, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [{"protocol": "vless",
                       "settings": {"vnext": [{"address": p.get("remote", "127.0.0.1"),
                                               "port": ps, "users": [{"id": uid, "encryption": "none"}]}]},
                       "streamSettings": {"network": transport}}],
    }
    return json.dumps({"server": server, "client": client}, indent=2)


@register_adapter
class XrayAdapter(UserspaceAdapter):
    engine_id = "xray"
    BINARY = "xray"
    PROFILES = {
        pid: ProfileSpec(pid, "vless",
                         lambda p: ["xray", "run", "-c", f"{CONF_DIR}/xray-{pid}-s.json"],
                         lambda p: ["xray", "run", "-c", f"{CONF_DIR}/xray-{pid}-c.json"],
                         config_renderer=_xray_config, config_ext="json",
                         probe="socks5", secrets=("user_id", "private_key"))
        for pid in ("vless_tcp", "vless_ws", "vless_grpc", "vless_reality",
                    "vless_vision_reality", "vless_xhttp", "vless_xhttp_reality")
    }


def _singbox_config(p: dict, spec: ProfileSpec) -> str:
    ps, pc = _ports(p)
    import json
    proto = spec.profile_id
    server = {"inbounds": [{"type": proto, "listen": "127.0.0.1", "listen_port": ps}],
              "outbounds": [{"type": "direct"}]}
    client = {"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": pc}],
              "outbounds": [{"type": proto,
                             "server": p.get("remote", "127.0.0.1"),
                             "server_port": ps}]}
    if proto == "tun":
        client = {"inbounds": [{"type": "tun", "interface_name": p.get("interface", "tun0")}],
                  "outbounds": [{"type": proto, "server": p.get("remote", "127.0.0.1"),
                                 "server_port": ps}]}
    return json.dumps({"server": server, "client": client}, indent=2)


@register_adapter
class SingboxAdapter(UserspaceAdapter):
    engine_id = "singbox"
    BINARY = "sing-box"
    PROFILES = {
        pid: ProfileSpec(pid, pid,
                         lambda p: ["sing-box", "run", "-c", f"{CONF_DIR}/singbox-{pid}-s.json"],
                         lambda p: ["sing-box", "run", "-c", f"{CONF_DIR}/singbox-{pid}-c.json"],
                         config_renderer=_singbox_config, config_ext="json",
                         probe=("tun" if pid == "tun" else "socks5"),
                         secrets=("password", "uuid"))
        for pid in ("shadowsocks", "trojan_tls", "tuic", "hysteria2", "tun")
    }


def _frp_config(p: dict, spec: ProfileSpec) -> str:
    ps, pc = _ports(p)
    kind = spec.profile_id
    server = """bindPort = %d
auth.token = "%s"
""" % (ps, p.get("auth_token", "tp-token"))
    remote = int(p.get("probe_port", pc))
    client = f"""serverAddr = "127.0.0.1"
serverPort = {ps}
auth.token = "{p.get('auth_token', 'tp-token')}"

[[proxies]]
name = "tp-{kind}"
type = "{ 'udp' if kind == 'udp' else 'tcp' }"
{'remotePort' if kind in ('tcp', 'udp', 'kcp', 'quic') else 'sk'} = {remote if kind in ('tcp', 'udp', 'kcp', 'quic') else '"tp-sk"'}
"""
    if kind in ("stcp", "xtcp"):
        client = f"""serverAddr = "127.0.0.1"
serverPort = {ps}
auth.token = "{p.get('auth_token', 'tp-token')}"

[[visitors]]
name = "tp-visitor"
type = "{kind}"
serverName = "tp-target"
bindAddr = "127.0.0.1"
bindPort = {remote}
"""
    return "---SERVER---\n" + server + "---CLIENT---\n" + client


@register_adapter
class FrpAdapter(UserspaceAdapter):
    engine_id = "frp"
    BINARY = "frpc"
    PROFILES = {
        pid: ProfileSpec(
            pid, pid,
            lambda p: ["frps", "-c", f"{CONF_DIR}/frp-{pid}-s.toml"],
            lambda p: ["frpc", "-c", f"{CONF_DIR}/frp-{pid}-c.toml"],
            config_renderer=_frp_config, config_ext="toml",
            probe=("udp" if pid == "udp" else "tcp"),
            secrets=("auth_token",))
        for pid in ("tcp", "udp", "kcp", "quic", "stcp", "xtcp")
    }


def _rathole_config(p: dict, spec: ProfileSpec) -> str:
    ps, pc = _ports(p)
    transport = spec.profile_id
    tconf = 'type = "tcp"'
    if transport == "udp":
        tconf = 'type = "udp"'
    elif transport in ("tls", "noise", "websocket"):
        tconf = f'type = "tcp"\n[transport.{transport}]'
    server = f"""[server]
bind_addr = "127.0.0.1"
bind_port = {ps}
default_token = "{p.get('token', 'tp-token')}"
"""
    remote = int(p.get("probe_port", pc))
    client = f"""[client]
remote_addr = "127.0.0.1:{ps}"
default_token = "{p.get('token', 'tp-token')}"

[transport]
{tconf}

[[services]]
name = "tp-{transport}"
type = "{ 'udp' if transport == 'udp' else 'tcp' }"
local_addr = "127.0.0.1:{ECHO_PORT}"
remote_addr = "127.0.0.1:{remote}"
"""
    return "---SERVER---\n" + server + "---CLIENT---\n" + client


@register_adapter
class RatholeAdapter(UserspaceAdapter):
    engine_id = "rathole"
    BINARY = "rathole"
    PROFILES = {
        pid: ProfileSpec(pid, pid,
                         lambda p: ["rathole", f"{CONF_DIR}/rathole-{pid}-s.toml"],
                         lambda p: ["rathole", f"{CONF_DIR}/rathole-{pid}-c.toml"],
                         config_renderer=_rathole_config, config_ext="toml",
                         probe=("udp" if pid == "udp" else "tcp"),
                         secrets=("token", "noise_key"))
        for pid in ("tcp", "udp", "tls", "noise", "websocket")
    }


@register_adapter
class ChiselAdapter(UserspaceAdapter):
    engine_id = "chisel"
    BINARY = "chisel"
    PROFILES = {
        pid: ProfileSpec(
            pid, pid,
            lambda p: ["chisel", "server", "--port", str(_ports(p)[0]),
                       "--auth", p.get("auth", "tp:tp")],
            {"tcp": lambda p: ["chisel", "client", "--auth", p.get("auth", "tp:tp"),
                               f"127.0.0.1:{_ports(p)[0]}", f"{int(p.get('probe_port', _ports(p)[1]))}:"],
             "udp": lambda p: ["chisel", "client", "--auth", p.get("auth", "tp:tp"),
                               f"127.0.0.1:{_ports(p)[0]}", f"{int(p.get('probe_port', _ports(p)[1]))}/:"],
             "socks5": lambda p: ["chisel", "client", "--auth", p.get("auth", "tp:tp"),
                                  f"127.0.0.1:{_ports(p)[0]}", "socks5:"],
             "reverse_tcp": lambda p: ["chisel", "client", "--auth", p.get("auth", "tp:tp"),
                                       f"127.0.0.1:{_ports(p)[0]}", f"R:{int(p.get('probe_port', _ports(p)[1]))}:"],
             "reverse_udp": lambda p: ["chisel", "client", "--auth", p.get("auth", "tp:tp"),
                                       f"127.0.0.1:{_ports(p)[0]}", f"R:{int(p.get('probe_port', _ports(p)[1]))}/:"],
             "reverse_socks5": lambda p: ["chisel", "client", "--auth", p.get("auth", "tp:tp"),
                                          f"127.0.0.1:{_ports(p)[0]}", "R:socks5"],
             }[pid],
            probe={"tcp": "tcp", "udp": "udp", "socks5": "socks5",
                   "reverse_tcp": "tcp", "reverse_udp": "udp", "reverse_socks5": "socks5"}[pid],
            secrets=("auth",))
        for pid in ("tcp", "udp", "socks5", "reverse_tcp", "reverse_udp", "reverse_socks5")
    }


@register_adapter
class WstunnelAdapter(UserspaceAdapter):
    engine_id = "wstunnel"
    BINARY = "wstunnel"
    PROFILES = {
        pid: ProfileSpec(
            pid, pid,
            lambda p: ["wstunnel", "--server", f"ws://127.0.0.1:{_ports(p)[0]}"],
            {"tcp": lambda p: ["wstunnel", "--local", f"tcp://127.0.0.1:{int(p.get('probe_port', _ports(p)[1]))}",
                               "--remote", f"tcp://127.0.0.1:{ECHO_PORT}",
                               "--server", f"ws://127.0.0.1:{_ports(p)[0]}"],
             "udp": lambda p: ["wstunnel", "--local", f"udp://127.0.0.1:{int(p.get('probe_port', _ports(p)[1]))}",
                               "--remote", f"udp://127.0.0.1:{ECHO_PORT}",
                               "--server", f"ws://127.0.0.1:{_ports(p)[0]}"],
             "socks5": lambda p: ["wstunnel", "--local", f"socks5://127.0.0.1:{_ports(p)[1]}",
                                  "--server", f"ws://127.0.0.1:{_ports(p)[0]}"],
             }[pid],
            probe={"tcp": "tcp", "udp": "udp", "socks5": "socks5"}[pid],
            secrets=())
        for pid in ("tcp", "udp", "socks5")
    }


def _waterwall_config(p: dict, spec: ProfileSpec) -> str:
    ps, pc = _ports(p)
    import json
    mode = spec.profile_id
    server = {"log": {"level": "info"},
              "inbounds": [{"type": "direct", "listen": "127.0.0.1", "port": ps}],
              "outbounds": [{"type": "blackhole"}]}
    client = {"log": {"level": "info"},
              "inbounds": [{"type": "direct", "listen": "127.0.0.1", "port": pc}],
              "outbounds": [{"type": "direct", "address": "127.0.0.1", "port": ps,
                             "tls": mode.endswith("tls")}]}
    if mode == "reverse":
        client["outbounds"][0]["reverse"] = True
    return json.dumps({"server": server, "client": client}, indent=2)


@register_adapter
class WaterwallAdapter(UserspaceAdapter):
    engine_id = "waterwall"
    BINARY = "waterwall"
    PROFILES = {
        pid: ProfileSpec(pid, pid,
                         lambda p: ["waterwall", "-c", f"{CONF_DIR}/waterwall-{pid}-s.json"],
                         lambda p: ["waterwall", "-c", f"{CONF_DIR}/waterwall-{pid}-c.json"],
                         config_renderer=_waterwall_config, config_ext="json",
                         probe="tcp", secrets=())
        for pid in ("direct", "reverse", "tls_mux")
    }


def _paqet_config(p: dict, spec: ProfileSpec) -> str:
    ps, pc = _ports(p)
    proto = "raw" if spec.profile_id == "raw_kcp" else "tcp"
    return f"""# paqet config — {spec.profile_id}
mode: pair
proto: {proto}
server:
  listen: 127.0.0.1:{ps}
  password: {p.get('password', 'REPLACE_ME')}
  notrack: true
client:
  listen: 127.0.0.1:{pc}
  socks5: true
  password: {p.get('password', 'REPLACE_ME')}
  server: 127.0.0.1:{ps}
"""


@register_adapter
class PaqetAdapter(UserspaceAdapter):
    engine_id = "paqet"
    BINARY = "paqet"
    PROFILES = {
        pid: ProfileSpec(pid, pid,
                         lambda p: ["paqet", "-c", f"{CONF_DIR}/paqet-{pid}.yml", "server"],
                         lambda p: ["paqet", "-c", f"{CONF_DIR}/paqet-{pid}.yml", "client"],
                         config_renderer=_paqet_config, config_ext="yml",
                         probe=("udp" if pid == "raw_kcp" else "socks5"),
                         secrets=("password",))
        for pid in ("socks5", "raw_kcp")
    }
