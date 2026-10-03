"""Canonical executor abstraction (P5 §6).

Engine logic never touches paramiko/subprocess directly — it goes through
one of these channels:
- LocalExecutor  : run on the local host (privileged panel host / containers)
- SSHExecutor    : run on a remote node over SSH (host-key pinning enforced)
- FakeExecutor   : recording executor for unit tests
NodeAgentExecutor may be added later without touching engine code.
"""
from __future__ import annotations


class LocalExecutor:
    """Runs commands via /bin/bash on the local host."""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        import subprocess
        try:
            p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                               timeout=timeout or self.timeout)
            return p.returncode, (p.stdout + p.stderr)[-4000:]
        except subprocess.TimeoutExpired:
            return 124, "timeout"


class SSHExecutor:
    """Paramiko channel with strict host-key policy (Gen1 security posture)."""

    def __init__(self, host: str, port: int = 22, username: str = "root",
                 password: str | None = None, key_filename: str | None = None):
        import paramiko                      # deferred import
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
    """Recording executor: scripted results by substring match, default else."""

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
