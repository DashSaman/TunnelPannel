"""SSH family + Hedioum + HajSaman adapters (P5 U3).

- SSH profiles (local/remote forward, dynamic SOCKS, TUN/TAP, autossh
  reverse) mirror the Gen2 mtf_kernel.sh SSH harness invocation shapes.
  Key-based auth only for passwordless automation; password auth is
  refused with an explicit BLOCKED-style precheck (never echoed).
- Hedioum/HajSaman are config-render wrappers distilled from the Gen3
  tunnelguard adapters (tfd/engines/*.py); marked PARTIAL — real pairing
  verification happens on Linux pairs in P14.
"""
from __future__ import annotations

from engines.adapters import register_adapter
from engines.adapters.kernel import CommandPlanAdapter

RUN_DIR = "/run/tunnelpannel"
CONF_DIR = "/etc/tunnelpannel"


class SshAdapter(CommandPlanAdapter):
    engine_id, profile_id = "ssh", "local_forward"

    def _ssh_base(self) -> list[str]:
        if not self.params.get("identity_file"):
            raise RuntimeError(
                "ssh automation requires key auth (identity_file); "
                "password flows must go through the credential service")
        return ["ssh", "-i", self.params["identity_file"],
                "-o", "StrictHostKeyChecking=yes",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                "-o", "ExitOnForwardFailure=yes", "-N"]

    def detect(self) -> bool:
        rc, _ = self.executor.run("command -v ssh")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("ssh -V 2>&1")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("ssh client missing")
        if not self.params.get("identity_file"):
            problems.append("identity_file required (password auth not automated)")
        if not (self.node_b or {}).get("host"):
            problems.append("no remote host")
        return problems

    def _forwards(self) -> list[str]:
        p = self.params
        host = self.node_b["host"]
        port = p.get("ssh_port", 22)
        user = p.get("remote_user", "root")
        f = []
        bind = int(p.get("bind_port", 14102))
        target = p.get("target", f"127.0.0.1:{p.get('target_port', 14080)}")
        profile = p.get("profile", self.profile_id)
        if profile == "local_forward":
            f = ["-L", f"127.0.0.1:{bind}:{target}"]
        elif profile == "remote_forward":
            f = ["-R", f"{bind}:{target}"]
        elif profile == "dynamic_socks":
            f = ["-D", f"127.0.0.1:{bind}"]
        elif profile in ("tun_l3", "tap_l2"):
            f = ["-w", p.get("tun_ids", "0:0")]
        elif profile == "reverse":                    # autossh keeps it alive
            f = ["-R", f"{bind}:{target}"]
        cmd = self._ssh_base() + f + [f"-p", f"{port}", f"{user}@{host}"]
        if profile == "reverse":
            cmd = ["autossh", "-M", "0"] + cmd[1:]
        return cmd

    def commands(self) -> list[tuple[str, str]]:
        argv = self._forwards()
        tag = f"ssh-{self.params.get('profile', self.profile_id)}"
        return [("start ssh tunnel",
                 f"nohup {' '.join(argv)} >{RUN_DIR}/{tag}.log 2>&1 & echo $! > {RUN_DIR}/{tag}.pid")]

    def rollback_commands(self) -> list[tuple[str, str]]:
        tag = f"ssh-{self.params.get('profile', self.profile_id)}"
        return [("stop", f"kill $(cat {RUN_DIR}/{tag}.pid 2>/dev/null) 2>/dev/null; "
                         f"rm -f {RUN_DIR}/{tag}.pid")]

    def probe_commands(self) -> list[str]:
        p = self.params
        profile = p.get("profile", self.profile_id)
        bind = int(p.get("bind_port", 14102))
        if profile == "dynamic_socks":
            return [f"curl -s -o /dev/null -w '%{{http_code}}' --socks5-hostname 127.0.0.1:{bind} "
                    f"--max-time 6 http://127.0.0.1:14080/"]
        if profile in ("tun_l3", "tap_l2"):
            iface = p.get("interface", "tun0")
            return [f"ping -c 3 -W 2 -I {iface} {p['probe_target']}"]
        return [f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 6 "
                f"http://127.0.0.1:{p.get('probe_port', bind)}/"]


@register_adapter
class SshDynamicSocks(SshAdapter):
    profile_id = "dynamic_socks"


@register_adapter
class SshRemoteForward(SshAdapter):
    profile_id = "remote_forward"


@register_adapter
class SshTunL3(SshAdapter):
    profile_id = "tun_l3"


@register_adapter
class SshTapL2(SshAdapter):
    profile_id = "tap_l2"


@register_adapter
class AutosshReverse(SshAdapter):
    profile_id = "reverse"


@register_adapter
class HedioumAdapter(CommandPlanAdapter):
    """Gen3 wrap: yml config + daemon; probe = socks CONNECT (pool_socks) or
    ping through TUN (tun profile)."""
    engine_id = "hedioum"
    profile_id = "tun"

    def detect(self) -> bool:
        rc, _ = self.executor.run("command -v hedioum && ls /sys/module/tun")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("hedioum --version 2>&1 | head -1")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("hedioum binary or tun module missing")
        if not self.params.get("pairing_token"):
            problems.append("pairing_token required")
        return problems

    def _yml(self) -> str:
        p = self.params
        ps, pc = int(p.get("server_port", 14111)), int(p.get("client_port", 14112))
        mode = "tun" if self.params.get("profile", self.profile_id) == "tun" else "pool_socks"
        iface = p.get("interface", "tp-hedioum")
        host = self.node_b["host"] if self.node_b else "127.0.0.1"
        token = p.get("pairing_token", "REPLACE_ME")
        if mode == "tun":
            subnet = p.get("subnet", "10.175.0.0/24")
            tail = "  tun: %s\n  routes: ['%s']" % (iface, subnet)
        else:
            tail = "  socks_listen: 127.0.0.1:%d" % pc
        return (
            "mode: %s\n"
            "server:\n"
            "  listen: 0.0.0.0:%d\n"
            "  token_file: %s/hedioum-token\n"
            "client:\n"
            "  server: %s:%d\n"
            "  token: %s\n"
            "%s\n" % (mode, ps, CONF_DIR, host, ps, token, tail)
        )

    def commands(self) -> list[tuple[str, str]]:
        conf = f"{CONF_DIR}/hedioum-{self.params.get('profile', self.profile_id)}.yml"
        tag = f"hedioum-{self.params.get('profile', self.profile_id)}"
        return [
            ("write yml", f"cat > {conf} <<'TPCONF'\n{self._yml()}TPCONF"),
            ("start server", f"nohup hedioum -c {conf} server >{RUN_DIR}/{tag}.log 2>&1 & "
                             f"echo $! > {RUN_DIR}/{tag}.pid"),
            ("start client", f"nohup hedioum -c {conf} client >{RUN_DIR}/{tag}-c.log 2>&1 & "
                             f"echo $! > {RUN_DIR}/{tag}-c.pid"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        tag = f"hedioum-{self.params.get('profile', self.profile_id)}"
        return [
            ("stop client", f"kill $(cat {RUN_DIR}/{tag}-c.pid 2>/dev/null) 2>/dev/null; rm -f {RUN_DIR}/{tag}-c.pid"),
            ("stop server", f"kill $(cat {RUN_DIR}/{tag}.pid 2>/dev/null) 2>/dev/null; rm -f {RUN_DIR}/{tag}.pid"),
            ("remove config", f"rm -f {CONF_DIR}/{tag}.yml {CONF_DIR}/hedioum-token"),
        ]

    def probe_commands(self) -> list[str]:
        p = self.params
        if self.params.get("profile", self.profile_id) == "tun":
            return [f"ping -c 3 -W 2 -I {p.get('interface', 'tp-hedioum')} {p['probe_target']}"]
        return [f"curl -s -o /dev/null -w '%{{http_code}}' --socks5-hostname 127.0.0.1:"
                f"{int(p.get('client_port', 14112))} --max-time 6 http://127.0.0.1:14080/"]

    def redacted_params(self) -> dict:
        out = dict(self.params)
        if "pairing_token" in out:
            out["pairing_token"] = "***REDACTED***"
        return out


@register_adapter
class HedioumPoolSocks(HedioumAdapter):
    profile_id = "pool_socks"


@register_adapter
class HajsamanAdapter(CommandPlanAdapter):
    """Gen3 wrap: slot-based transport (full/sit/wg); probe ping (ping6 for sit)."""
    engine_id = "hajsaman"
    profile_id = "full"

    def detect(self) -> bool:
        rc, _ = self.executor.run("command -v hajsaman && ls /sys/module/sit")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("hajsaman --version 2>&1 | head -1")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("hajsaman binary or sit module missing")
        if not self.params.get("slot_conf"):
            problems.append("slot_conf required")
        return problems

    def commands(self) -> list[tuple[str, str]]:
        p = self.params
        conf = f"{CONF_DIR}/hajsaman-{p.get('profile', self.profile_id)}.conf"
        tag = f"hajsaman-{p.get('profile', self.profile_id)}"
        return [
            ("write slot conf", f"cat > {conf} <<'TPCONF'\n{p['slot_conf']}TPCONF"),
            ("start", f"nohup hajsaman -c {conf} >{RUN_DIR}/{tag}.log 2>&1 & "
                      f"echo $! > {RUN_DIR}/{tag}.pid"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        tag = f"hajsaman-{self.params.get('profile', self.profile_id)}"
        return [
            ("stop", f"kill $(cat {RUN_DIR}/{tag}.pid 2>/dev/null) 2>/dev/null; rm -f {RUN_DIR}/{tag}.pid"),
            ("remove conf", f"rm -f {CONF_DIR}/{tag}.conf"),
        ]

    def probe_commands(self) -> list[str]:
        p = self.params
        if p.get("profile", self.profile_id) == "sit":
            return [f"ping -6 -c 3 -W 2 -I {p.get('interface', 'tp-hjsit')} {p['probe_target']}"]
        return [f"ping -c 3 -W 2 -I {p.get('interface', 'tp-hj')} {p['probe_target']}"]


@register_adapter
class HajsamanSit(HajsamanAdapter):
    profile_id = "sit"


@register_adapter
class HajsamanWg(HajsamanAdapter):
    profile_id = "wg"
