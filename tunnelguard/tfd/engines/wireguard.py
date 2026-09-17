"""TunnelGuard — WireGuard engine adapter (kernel module via wg-quick).

Config keys (tunnel.config JSON):
  private_key, peer_public_key, listen_port, endpoint_host, endpoint_port,
  allowed_ips (comma separated), keepalive (default 25), table (optional)

Precheck honestly reports: missing binaries, missing kernel module, or a
private key that is not a valid 44-char wg base64 key.
"""
from __future__ import annotations

import time

from .base import EngineAdapter

CONF_PATH = None  # resolved lazily (config.WG_CONF_DIR)


class WireGuardAdapter(EngineAdapter):
    name = "wireguard"

    # ------------------------------------------------------------- render
    @property
    def _conf_dir(self) -> str:
        from .. import config
        return config.WG_CONF_DIR

    def render(self) -> dict[str, str]:
        c = self.cfg
        allowed = c.get("allowed_ips") or f"{self.t.get('remote_ip')}/32"
        if isinstance(allowed, list):
            allowed = ",".join(allowed)
        content = (
            "[Interface]\n"
            f"Address = {self.t.get('local_ip')}/32\n"
            f"PrivateKey = {c.get('private_key', '<PRIVATE_KEY>')}\n"
            f"ListenPort = {c.get('listen_port', 51820)}\n"
            f"MTU = {self.t.get('mtu') or 1420}\n"
            f"Table = {c.get('table', 'off')}\n"
            "\n[Peer]\n"
            f"PublicKey = {c.get('peer_public_key', '<PEER_PUBLIC_KEY>')}\n"
            f"Endpoint = {c.get('endpoint_host')}:{c.get('endpoint_port', 51820)}\n"
            f"AllowedIPs = {allowed}\n"
            f"PersistentKeepalive = {c.get('keepalive', 25)}\n"
        )
        return {f"{self._conf_dir}/{self.iface}.conf": content}

    # ----------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        problems = []
        if not self._which("wg") or not self._which("wg-quick"):
            problems.append("wireguard-tools not installed (apt install wireguard-tools)")
        probe = self.exec(["ip", "link", "add", "tf-wg-precheck",
                           "type", "wireguard"], timeout=10)
        if probe.returncode != 0:
            problems.append(
                "kernel WireGuard interface unavailable "
                f"({(probe.stderr or '').strip()[:100]}); "
                "install 'wireguard' package / check kernel modules")
        else:
            self.exec(["ip", "link", "del", "tf-wg-precheck"])
        pk = self.cfg.get("private_key") or ""
        if pk and len(pk.strip()) != 44:
            problems.append("private_key looks invalid (expect 44-char wg base64)")
        ppk = self.cfg.get("peer_public_key") or ""
        if ppk and len(ppk.strip()) != 44:
            problems.append("peer_public_key looks invalid (expect 44-char wg base64)")
        return problems

    # ---------------------------------------------------------------- up
    def up(self) -> list[str]:
        executed = []
        for path, content in self.render().items():
            self.write_artifact(path, content)
            executed.append(f"write {path}")
        cp = self._run_or_fail(["wg-quick", "up", self.iface], "wg-quick up")
        executed.append(f"wg-quick up {self.iface} (rc={cp.returncode})")
        return executed

    # -------------------------------------------------------------- down
    def down(self) -> list[str]:
        cp = self.exec(["wg-quick", "down", self.iface], timeout=20)
        note = "already down" if cp.returncode != 0 else "ok"
        return [f"wg-quick down {self.iface} ({note})"]

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        up = self._iface_exists()
        extra: dict = {}
        if up:
            cp = self.exec(["wg", "show", self.iface, "dump"], timeout=10)
            if cp.returncode == 0:
                lines = cp.stdout.strip().splitlines()
                if len(lines) >= 2:
                    cols = lines[1].split("\t")
                    try:
                        hs = int(cols[4] or 0)
                        extra = {
                            "endpoint": cols[2] or None,
                            "last_handshake_age_s": int(time.time() - hs) if hs else None,
                            "rx_bytes": int(cols[5] or 0),
                            "tx_bytes": int(cols[6] or 0),
                        }
                    except (IndexError, ValueError):
                        pass
        return {"up": up, "detail": "wg interface present" if up else "interface missing",
                "extra": extra}
