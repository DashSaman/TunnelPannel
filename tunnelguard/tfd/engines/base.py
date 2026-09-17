"""TunnelGuard — engine adapter base class.

Every engine implements the same contract:

    render()   -> {abs_path: content}   reviewable artifacts ("final config")
    precheck() -> [problems]            empty list = ready to run
    up()       -> executed commands     brings the tunnel interface UP
    down()     -> executed commands
    status()   -> {up: bool, detail: str, extra: {...}}

Adapters never run commands themselves — they call self.exec(cmd), which the
caller controls. That makes every adapter unit-testable (recording executor)
and lets the selftest harness wrap commands in `ip netns exec` namespaces.

Honest-limit principle: if a precheck cannot be verified locally (e.g. an
upstream firewall dropping proto 41 for SIT), the adapter says so explicitly
in its precheck output instead of pretending everything is fine.
"""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod

from .. import config

class AdapterError(RuntimeError):
    pass


class EngineAdapter(ABC):
    name = "base"

    def __init__(self, tunnel: dict, executor=None):
        self.t = tunnel
        raw = tunnel.get("config")
        if isinstance(raw, dict):          # tolerate both dict and JSON str
            self.cfg: dict = raw
        else:
            self.cfg: dict = json.loads(raw or "{}")
        self.iface: str = tunnel.get("iface") or f"tf{tunnel.get('id', 0)}"
        self._exec = executor or _default_exec

    # ------------------------------------------------------------ plumbing
    def exec(self, cmd: list[str] | str, timeout: float = 30.0,
             check: bool = False) -> subprocess.CompletedProcess:
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        return self._exec(cmd, timeout)

    def _run_or_fail(self, cmd, what: str, timeout: float = 30.0):
        cp = self.exec(cmd, timeout=timeout)
        if cp.returncode != 0:
            raise AdapterError(
                f"{what} failed (rc={cp.returncode}): {cp.stderr.strip() or cp.stdout.strip()}"
            )
        return cp

    def write_artifact(self, path: str, content: str, mode: int = 0o600) -> str:
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        return path

    # ------------------------------------------------------------ contract
    @abstractmethod
    def render(self) -> dict[str, str]: ...
    @abstractmethod
    def precheck(self) -> list[str]: ...
    @abstractmethod
    def up(self) -> list[str]: ...
    @abstractmethod
    def down(self) -> list[str]: ...
    @abstractmethod
    def status(self) -> dict: ...

    # ------------------------------------------------------------ helpers
    def _iface_exists(self) -> bool:
        cp = self.exec(["ip", "-o", "link", "show", "dev", self.iface])
        return cp.returncode == 0

    def _iface_counters(self) -> dict | None:
        cp = self.exec(
            ["cat", f"/sys/class/net/{self.iface}/statistics/rx_bytes"], timeout=5)
        if cp.returncode != 0:
            return None
        rx = int(cp.stdout.strip() or 0)
        cp2 = self.exec(
            ["cat", f"/sys/class/net/{self.iface}/statistics/tx_bytes"], timeout=5)
        tx = int(cp2.stdout.strip() or 0) if cp2.returncode == 0 else 0
        return {"rx_bytes": rx, "tx_bytes": tx}

    def _which(self, binary: str) -> str | None:
        return shutil.which(binary)

    def _probe_cycle(self) -> dict:
        """Standard probe against remote_ip through the tunnel source IP."""
        from .. import probes
        target = self.t.get("remote_ip")
        source = self.t.get("local_ip")
        s = self._settings()
        if not target:
            return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                    "ok": False, "detail": "remote_ip not configured"}
        res = probes.ping_cycle(target, int(s.get("probe_count", 5)),
                                float(s.get("probe_timeout_s", 2)), source=source)
        if not res["ok"] and s.get("tcp_fallback_enabled"):
            tcp = probes.tcp_cycle(target, int(s.get("tcp_fallback_port", 443)),
                                   source=source,
                                   timeout_s=float(s.get("probe_timeout_s", 2)))
            if tcp["ok"]:
                res = {**tcp, "method": "tcp"}
        return res

    def _settings(self) -> dict:
        from .. import db as dbm
        return dbm.get_settings()


def _default_exec(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
