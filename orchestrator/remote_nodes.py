"""Encrypted canonical node access and SHA-256 pinned command channels."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import socket

from cryptography.fernet import Fernet
import paramiko


def _cipher():
    secret = os.environ.get("TP_SECRET_KEY", "")
    if len(secret) < 16:
        raise ValueError("installation secret is not configured")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def encrypt_credentials(credentials: dict) -> str:
    return _cipher().encrypt(json.dumps(credentials).encode()).decode()


def decrypt_credentials(ciphertext: str) -> dict:
    return json.loads(_cipher().decrypt(ciphertext.encode()))


def verify_host_key(expected: str, raw: bytes):
    actual = hashlib.sha256(raw).digest()
    value = (base64.b64decode(expected[7:] + "=" * (-len(expected[7:]) % 4))
             if expected.startswith("SHA256:") else bytes.fromhex(expected))
    if not value or not hmac.compare_digest(value, actual):
        raise ValueError("SSH host key does not match the pinned fingerprint")


def observe_host_key(host: str, port: int) -> str:
    """Initial trust only; no credentials are sent during key observation.

    The subsequent authenticated connection verifies this exact key again.
    Operators may instead supply a fingerprint verified out of band.
    """
    with socket.create_connection((host, port), timeout=10) as connection:
        transport = paramiko.Transport(connection)
        try:
            transport.start_client(timeout=10)
            return hashlib.sha256(transport.get_remote_server_key().asbytes()).hexdigest()
        finally:
            transport.close()


class _PinnedPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint

    def missing_host_key(self, client, hostname, key):
        verify_host_key(self.fingerprint, key.asbytes())
        client.get_host_keys().add(hostname, key.get_name(), key)


class NodeRemote:
    """Legacy deployment-body compatible channel without TOFU or legacy DB."""
    def __init__(self, endpoint, credentials, deadline=None, cancelled=None):
        self.endpoint, self.credentials = endpoint, credentials
        self.deadline, self.cancelled = deadline, cancelled
        self.observer = None
        self._observing = False
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(_PinnedPolicy(endpoint["host_key_fingerprint"]))

    def connect(self):
        from plan_executor.executor import load_private_key
        options = {"hostname": self.endpoint["host"], "port": self.endpoint["port"],
                   "username": self.endpoint["ssh_username"], "timeout": 15,
                   "auth_timeout": 15, "banner_timeout": 15,
                   "look_for_keys": False, "allow_agent": False}
        if self.credentials["auth_method"] == "PASSWORD":
            options["password"] = self.credentials["secret"]
        else:
            options["pkey"] = load_private_key(self.credentials["secret"])
        self.client.connect(**options)
        self.client.get_transport().set_keepalive(20)
        return self

    def close(self):
        self.client.close()

    def scrub(self, message):
        for key in ("secret", "sudo_password"):
            if self.credentials.get(key):
                message = message.replace(self.credentials[key], "<REDACTED>")
        return message

    def run(self, command, *, root=False, timeout=60, check=True):
        import shlex
        if self.observer and not self._observing:
            self._observing = True
            try:
                self.observer(command)
            finally:
                self._observing = False
        if self.cancelled and self.cancelled():
            raise RuntimeError("benchmark cancelled")
        if self.deadline:
            timeout = min(timeout, max(1, int(self.deadline - time.monotonic())))
            if time.monotonic() >= self.deadline:
                raise TimeoutError("benchmark stage deadline exceeded")
        final = "bash -lc " + shlex.quote(command)
        if root and self.endpoint["ssh_username"] != "root":
            final = "sudo -n " + final
        _, stdout, stderr = self.client.exec_command(final, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        if check and rc:
            raise RuntimeError(self.scrub((err or out or f"remote exit {rc}")[-2000:]))
        return {"code": rc, "stdout": self.scrub(out), "stderr": self.scrub(err)}


def node_access(session, node_id):
    from core.models import Node, SecretReference
    node = session.get(Node, node_id)
    if node is None:
        raise ValueError("registered node was not found")
    secret = session.get(SecretReference, node.secret_ref) if node.secret_ref else None
    if secret is None or not node.host_key_fingerprint:
        raise ValueError("node credentials and pinned host key are required")
    endpoint = {"id": node.id, "name": node.name, "host": node.host,
                "port": node.ssh_port, "ssh_username": node.ssh_username,
                "host_key_fingerprint": node.host_key_fingerprint}
    return endpoint, decrypt_credentials(secret.ciphertext)


def discover(endpoint, credentials):
    remote = NodeRemote(endpoint, credentials).connect()
    try:
        os_name = remote.run("uname -s")["stdout"].strip().lower()
        machine = remote.run("uname -m")["stdout"].strip()
        privileged = remote.run("id -u", root=True)["stdout"].strip() == "0"
        binaries = remote.run("for b in ip ping wg wg-quick gost ssh openvpn swanctl xray frpc frps "
                              "sing-box rathole chisel wstunnel paqet hedioum hajsaman waterwall; "
                              "do command -v \"$b\" >/dev/null && echo \"$b\"; done; true")["stdout"].split()
        modules = remote.run("ls /sys/module")["stdout"].split()
        ipv6 = remote.run("ip -6 -o addr show scope global")["stdout"]
        from orchestrator.host_inventory import scan
        coexistence = scan(remote)
        return {"node_id": endpoint["id"], "os": os_name,
                "arch": {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine),
                "privileged": privileged, "binaries": binaries,
                "kernel_modules": modules, "ipv6_addresses": ipv6.strip(),
                "coexistence": coexistence}
    finally:
        remote.close()
