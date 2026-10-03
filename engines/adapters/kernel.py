"""Real kernel-tunnel adapters (P5b) — command-planning pattern.

Each adapter builds the actual Linux commands (the same command shapes the
Gen1 executor and Gen2 mtf_kernel.sh harness already proved), runs them
through the :class:`Executor` protocol (SSH in production, recording fake
in tests), probes the real data plane (ping through the tunnel), and rolls
back with the inverse commands in reverse order.

No network mutation happens on Windows/CI: everything goes through the
executor channel, so unit tests assert the *command stream* — the Linux
behavior itself is exercised by the privileged/E2E tiers.
"""
from __future__ import annotations

from engines.adapters import (EngineAdapter, PlanAction, ProbeResult,
                              register_adapter)


class SSHExecutor:
    """Paramiko-backed command channel (production). Reuses the Gen1
    security posture: host-key pinning happens at connection setup."""

    def __init__(self, host: str, port: int = 22, username: str = "root",
                 password: str | None = None, key_filename: str | None = None):
        import paramiko                      # deferred: tests use fakes
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self._client.connect(host, port=port, username=username,
                             password=password, key_filename=key_filename,
                             look_for_keys=False, allow_agent=False, timeout=15)

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        return rc, (stdout.read() + stderr.read()).decode(errors="replace")[-4000:]

    def close(self) -> None:
        self._client.close()


class FakeExecutor:
    """Recording executor for tests: returns scripted results."""

    def __init__(self, results: dict[str, tuple[int, str]] | None = None,
                 default: tuple[int, str] = (0, "")):
        self.commands: list[str] = []
        self.results = results or {}
        self.default = default

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        self.commands.append(cmd)
        for needle, res in self.results.items():
            if needle in cmd:
                return res
        return self.default


class CommandPlanAdapter(EngineAdapter):
    """Shared machinery: plan from a declarative command list."""

    def commands(self) -> list[tuple[str, str]]:
        """[(why, cmd), ...] to apply, in order."""
        raise NotImplementedError

    def rollback_commands(self) -> list[tuple[str, str]]:
        """Inverse commands; executed in REVERSE order."""
        raise NotImplementedError

    def probe_commands(self) -> list[str]:
        raise NotImplementedError

    # ── EngineAdapter ──
    def plan(self) -> list[PlanAction]:
        return [PlanAction(verb="RUN", target=why, detail=cmd)
                for why, cmd in self.commands()]

    def install(self) -> None:            # kernel methods need no packages
        pass

    def configure(self) -> None:
        for why, cmd in self.commands():
            rc, out = self.executor.run(cmd)
            if rc != 0:
                raise RuntimeError(f"configure failed ({why}): {out[-200:]}")

    def start(self) -> None:
        rc, out = self.executor.run(f"ip link set {self.params['interface']} up")
        if rc != 0:
            raise RuntimeError(f"start failed: {out[-200:]}")

    def probe(self) -> ProbeResult:
        for cmd in self.probe_commands():
            rc, out = self.executor.run(cmd, timeout=10)
            if rc != 0:
                return ProbeResult(ok=False,
                                   evidence=f"data-plane probe failed: {cmd} -> {out[-160:]}")
        return ProbeResult(ok=True, evidence=f"data-plane probe passed via {self.node_a.get('name', 'node-a')}")

    def metrics(self) -> dict:
        rc, out = self.executor.run(
            f"ping -c 4 -W 2 {self.params.get('probe_target', '')} 2>/dev/null | tail -1")
        if rc != 0 or "rtt" not in out:
            return {}
        import re
        fields = re.findall(r"\d+\.?\d*", out.split("=")[-1])
        if len(fields) < 4:                               # min/avg/max/mdev
            return {}
        return {"rtt_avg_ms": float(fields[1]), "rtt_max_ms": float(fields[2])}

    def stop(self) -> None:
        self.executor.run(f"ip link set {self.params['interface']} down 2>/dev/null; true")

    def remove(self) -> None:
        for why, cmd in reversed(self.rollback_commands()):
            self.executor.run(cmd)

    def rollback(self) -> None:
        # tolerate partial application: `2>/dev/null; true` keeps unwinding
        for why, cmd in reversed(self.rollback_commands()):
            self.executor.run(cmd + " 2>/dev/null; true" if not cmd.endswith("true") else cmd)


@register_adapter
class WireGuardAdapter(CommandPlanAdapter):
    engine_id = "wireguard"
    profile_id = "default"

    def detect(self) -> bool:
        rc, _ = self.executor.run("command -v wg && command -v wg-quick")
        if rc != 0:
            return False
        rc, _ = self.executor.run("modprobe wireguard 2>/dev/null; ls /sys/module/wireguard")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("wg --version; ip -o link show type wireguard")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("wireguard binaries/kernel module missing")
        if not (self.params.get("endpoint_b") or (self.node_b or {}).get("host")):
            problems.append("no peer endpoint (endpoint_b / node_b.host)")
        if not self.params.get("subnet"):
            problems.append("no inner subnet allocated")
        return problems

    def commands(self) -> list[tuple[str, str]]:
        p = self.params
        iface, port = p["interface"], p["port"]
        inner_a, inner_b = p["inner_ip_a"], p["inner_ip_b"]
        endpoint_b = p.get("endpoint_b") or f"{self.node_b['host']}:{port}"
        return [
            ("create interface", f"ip link add {iface} type wireguard"),
            ("generate keys",
             f"wg genkey | tee /etc/wireguard/{iface}.key | wg pubkey > /etc/wireguard/{iface}.pub"),
            ("configure listen",
             f"wg set {iface} listen-port {port} private-key /etc/wireguard/{iface}.key"),
            ("assign address", f"ip addr add {inner_a} dev {iface}"),
            ("peer config placeholder",
             f"wg set {iface} peer $({{ cat /etc/wireguard/{iface}.peer || echo PENDING }}) "
             f"endpoint {endpoint_b} allowed-ips {p['subnet']}"),
            ("mtu", f"ip link set dev {iface} mtu {p.get('mtu', 1420)} up"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        iface = self.params["interface"]
        return [
            ("delete interface", f"ip link del {iface}"),
            ("remove keys", f"rm -f /etc/wireguard/{iface}.key /etc/wireguard/{iface}.pub"),
        ]

    def probe_commands(self) -> list[str]:
        return [f"ping -c 3 -W 2 -I {self.params['interface']} {self.params['probe_target']}"]


@register_adapter
class GreAdapter(CommandPlanAdapter):
    engine_id = "gre"
    profile_id = "default"

    def detect(self) -> bool:
        rc, _ = self.executor.run("modprobe ip_gre 2>/dev/null; ls /sys/module/ip_gre")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("ip -d link show type gre")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("ip_gre kernel module missing")
        if not (self.node_b or {}).get("host"):
            problems.append("no remote host for the GRE peer")
        return problems

    def commands(self) -> list[tuple[str, str]]:
        p = self.params
        iface = p["interface"]
        remote = self.node_b["host"]
        local = p.get("local_ip", "")
        local_arg = f"local {local} " if local else ""
        return [
            ("create tunnel",
             f"ip tunnel add {iface} mode gre remote {remote} {local_arg}ttl 64"),
            ("assign address", f"ip addr add {p['inner_ip_a']} dev {iface}"),
            ("bring up", f"ip link set {iface} up mtu {p.get('mtu', 1476)}"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        return [("delete tunnel", f"ip tunnel del {self.params['interface']}")]

    def probe_commands(self) -> list[str]:
        return [f"ping -c 3 -W 2 -I {self.params['interface']} {self.params['probe_target']}"]
