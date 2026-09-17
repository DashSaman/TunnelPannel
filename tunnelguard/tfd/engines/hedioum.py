"""TunnelGuard — Hedioum Dynamic Pool Tunnel engine adapter.

Hedioum (github.com/hedioum/Hedioum-Pool-Tunnel) is a userspace connection
multiplexer: the Iran hub exposes a local SOCKS5 ingress (one port per
foreign node) and optionally a TUN interface (hedioum0 style, per-node /24),
and multiplexes traffic over an authenticated, encrypted connection pool
whose physical pipes wear DPI-evasion mimics (SSH, TLS, mail, DB, panels).

This adapter runs on the IRAN hub node and manages ONE foreign node
(one TunnelGuard tunnel == one Hedioum foreign node).

Config keys (tunnel.config JSON):
  pairing_token          v2 pairing token printed by `setup-foreign`
                         (base64url JSON: v/ip/auth/persona/sni/eps).
                         When present it wins over manual fields.
  foreign_ip             manual mode: foreign (egress) server IP/hostname
  foreign_port           manual mode: the mimic port the foreign listens on
  auth_token             manual mode: 32-hex auth secret (v1 token)
  mimic                  manual mode: ssh|tls|smtp|imap (default ssh)
  socks_port             local SOCKS5 ingress port (default 40001)
  tun_enabled            expose a TUN interface for this node (routing!)
  tun_addr               TUN gateway CIDR, default 10.200.<tid>.1/24
  dns_enabled            run the leak-free :53 forwarder on the TUN gateway
  min_connections        pool warm-up size (default 10)
  max_connections        pool ceiling (default 20)
  bandwidth_limit_mbps   per-connection target before scale-up (default 8)
  bandwidth_jitter_mbps  Chaos-Mesh fluctuation (default 2)
  probe_target           through-tunnel probe target host (default 1.1.1.1)
  probe_port             through-tunnel probe target port (default 443)
  standalone             run the binary directly (no systemd) — labs/tests
  binary_path            override hedioum-tunnel binary location

Honest engineering notes:
- The config file /etc/hedioum/hedioum.json holds ALL foreign nodes of a
  hub. The adapter MERGES its node (matched by alias) and preserves any
  other nodes already present — it never clobbers a foreign co-tenant.
- Without tun_enabled the tunnel is SOCKS5-only: healthy probes and app
  traffic through 127.0.0.1:socks_port work, but the kernel cannot route
  the VIP through it, so the FSM will not promote it to the ACTIVE slot.
- On a hub where Hedioum is not yet installed, precheck says exactly that
  (installer provides scripts/install_hedioum.sh).
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import signal
import socket
import subprocess
import time

from .base import EngineAdapter, AdapterError
from .. import config as appconfig

DEFAULT_BINARY = "/usr/local/bin/hedioum-tunnel"
CONFIG_PATH = os.environ.get("TF_HEDIOUM_CONF", "/etc/hedioum/hedioum.json")
PID_FILE_FMT = "{data_dir}/hedioum-{alias}.pid"

_TOKEN_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_popen = subprocess.Popen  # patch point for tests (keep global subprocess clean)


def decode_pairing_token(token: str) -> dict | None:
    """Decode a Hedioum v2 pairing token (mirrors internal/pairing/token.go).
    Returns {exit_ip, auth_key, persona, sni, endpoints:{mimic:port}}
    or None for a legacy 32-hex v1 token / malformed input."""
    token = (token or "").strip()
    if not token or _TOKEN_RE.match(token):
        return None
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        payload = json.loads(raw)
        if int(payload.get("v", 0)) != 2:
            return None
        eps = {str(k): int(v) for k, v in (payload.get("eps") or {}).items()}
        return {
            "exit_ip": str(payload.get("ip") or ""),
            "auth_key": str(payload.get("auth") or ""),
            "persona": str(payload.get("persona") or ""),
            "sni": str(payload.get("sni") or ""),
            "endpoints": eps,
        }
    except (binascii.Error, ValueError, TypeError, json.JSONDecodeError):
        return None


class HedioumAdapter(EngineAdapter):
    name = "hedioum"

    # proxy tunnel: routing capability depends on TUN mode
    @property
    def routing_capable(self) -> bool:
        return bool(self.cfg.get("tun_enabled"))

    # ------------------------------------------------------------- identity
    @property
    def alias(self) -> str:
        # one TunnelGuard tunnel == one Hedioum foreign node
        return re.sub(r"[^A-Za-z0-9_.-]", "_",
                      self.t.get("name") or f"tg{self.t.get('id', 0)}")

    @property
    def socks_port(self) -> int:
        return int(self.cfg.get("socks_port") or 40001)

    def _resolved(self) -> dict:
        """Merge pairing-token fields over manual config fields."""
        out = dict(self.cfg)
        # legacy v1 flow: a bare 32-hex secret in pairing_token IS the auth
        # token — map it, otherwise the hub would dial with an empty secret.
        tok_raw = (out.get("pairing_token") or "").strip()
        if tok_raw and _TOKEN_RE.match(tok_raw) and not out.get("auth_token"):
            out["auth_token"] = tok_raw
        tok = decode_pairing_token(self.cfg.get("pairing_token") or "")
        if tok:
            out.setdefault("foreign_ip", tok["exit_ip"])
            out["auth_token"] = tok["auth_key"] or out.get("auth_token")
            if tok["endpoints"]:
                first = sorted(tok["endpoints"].items(),
                               key=lambda kv: 0 if kv[0] == "ssh" else 1)
                mimic, port = first[0]
                out.setdefault("foreign_port", port)
                out.setdefault("mimic", mimic)
                # keep the whole endpoint map for multi-mimic dialing
                out["_endpoints"] = tok["endpoints"]
            if tok.get("persona"):
                out.setdefault("persona", tok["persona"])
        return out

    # --------------------------------------------------------------- render
    def _node(self) -> dict:
        r = self._resolved()
        foreign_ip = r.get("foreign_ip") or self.t.get("remote_host") or ""
        foreign_port = int(r.get("foreign_port") or 22)
        mimic = r.get("mimic") or "ssh"
        endpoints = [{"target": f"{foreign_ip}:{foreign_port}",
                      "mimic": mimic}]
        eps = r.get("_endpoints") or {}
        if len(eps) > 1:
            endpoints = [{"target": f"{foreign_ip}:{int(p)}", "mimic": m}
                         for m, p in eps.items()]
        tid = int(self.t.get("id", 0) or 0)
        return {
            "alias": self.alias,
            "target_ip": foreign_ip,
            "target_port": foreign_port,
            "local_socks_port": self.socks_port,
            "socks_bind": r.get("socks_bind") or "127.0.0.1",
            "tun_enabled": bool(r.get("tun_enabled")),
            "tun_name": r.get("tun_name") or self.iface,
            "tun_addr": r.get("tun_addr") or f"10.200.{tid % 200 + 10}.1/24",
            "dns_enabled": bool(r.get("dns_enabled")),
            "min_connections": int(r.get("min_connections") or 10),
            "max_connections": int(r.get("max_connections") or 20),
            "bandwidth_limit_mbps": int(r.get("bandwidth_limit_mbps") or 8),
            "bandwidth_jitter_mbps": int(r.get("bandwidth_jitter_mbps") or 2),
            "auth_token": r.get("auth_token") or "",
            "endpoints": endpoints,
        }

    def _read_hub_config(self) -> dict | None:
        cp = self.exec(["cat", CONFIG_PATH], timeout=10)
        if cp.returncode != 0:
            return None
        try:
            data = json.loads(cp.stdout or "{}")
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def render(self) -> dict[str, str]:
        """Merged hub config artifact. Preserves foreign co-tenant nodes."""
        existing = self._read_hub_config() or {}
        role = existing.get("role") or "iran"
        nodes = [n for n in (existing.get("foreign_nodes") or [])
                 if isinstance(n, dict) and n.get("alias") != self.alias]
        nodes.append(self._node())
        merged = dict(existing)
        merged["role"] = role
        merged["foreign_nodes"] = nodes
        return {
            CONFIG_PATH: json.dumps(merged, indent=2, ensure_ascii=False),
            f"{appconfig.DATA_DIR}/hedioum/{self.alias}-node.json":
                json.dumps(self._node(), indent=2, ensure_ascii=False),
        }

    # ------------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        problems: list[str] = []
        binary = self.cfg.get("binary_path") or DEFAULT_BINARY
        if not (os.path.exists(binary) or self._which("hedioum-tunnel")):
            problems.append(
                "hedioum-tunnel binary not found — install it first "
                "(scripts/install_hedioum.sh, or hedioum-tunnel install on "
                "the foreign first, then the hub)")
        r = self._resolved()
        if not (r.get("pairing_token") or "").strip() and not (
                r.get("foreign_ip") or self.t.get("remote_host")):
            problems.append(
                "no pairing_token and no foreign_ip — paste the v2 pairing "
                "token from `hedioum-tunnel setup-foreign` or fill the "
                "manual fields")
        if r.get("auth_token") and not _TOKEN_RE.match(r["auth_token"]):
            problems.append("auth_token looks invalid (expect 32 hex chars)")
        if not r.get("auth_token"):
            problems.append("auth_token resolves to empty — paste a pairing "
                            "token (v2 or 32-hex) or fill auth_token")
        if not (r.get("pairing_token") or "").strip() and not r.get("foreign_port"):
            problems.append("foreign_port missing (the mimic port the "
                            "foreign listens on, e.g. 22 for the SSH mimic)")
        tok_raw = (r.get("pairing_token") or "").strip()
        if tok_raw and decode_pairing_token(tok_raw) is None \
                and not _TOKEN_RE.match(tok_raw):
            problems.append("pairing_token is neither a v2 token nor a "
                            "legacy 32-hex key — copy it again from "
                            "`setup-foreign` output")
        # hub config co-tenancy: refuse to run against a FOREIGN config
        existing = self._read_hub_config()
        if existing and existing.get("role") == "foreign":
            problems.append(
                f"{CONFIG_PATH} has role=foreign — this adapter manages a "
                "HUB (iran role); TunnelGuard and the foreign node must "
                "not share this box's hedioum config")
        # port conflicts
        for port, what in ((self.socks_port, "SOCKS5 ingress"),):
            if self._port_in_use(port):
                problems.append(
                    f"port {port} already in use — the {what} for alias "
                    f"'{self.alias}' needs a free local port")
        # honest routing note
        if not self.routing_capable:
            problems.append(
                "SOCKS-only mode (tun_enabled=false): probes and per-app "
                "traffic work, but the kernel cannot route the virtual IP "
                "through this tunnel — it will never be promoted ACTIVE "
                "for VIP failover. Enable TUN mode for routing.")
        return problems

    def _port_in_use(self, port: int) -> bool:
        cp = self.exec(["ss", "-tln"], timeout=10)
        if cp.returncode == 0:
            for line in cp.stdout.splitlines():
                cols = line.split()
                if len(cols) >= 4 and cols[3] in (
                        f"127.0.0.1:{port}", f"*:{port}", f"0.0.0.0:{port}"):
                    # our own previous standalone instance is fine (restart)
                    if not self._pid_alive():
                        return True
        return False

    # ------------------------------------------------------------------ up
    def _binary(self) -> str:
        binary = self.cfg.get("binary_path") or DEFAULT_BINARY
        if not os.path.exists(binary):
            w = self._which("hedioum-tunnel")
            if w:
                binary = w
        return binary

    def _up_systemd(self) -> list[str]:
        executed = []
        cp = self.exec(["systemctl", "restart", "hedioum"], timeout=40)
        if cp.returncode != 0:
            raise AdapterError(
                f"systemctl restart hedioum failed: "
                f"{(cp.stderr or cp.stdout).strip()[:200]}")
        executed.append("systemctl restart hedioum (rc=0)")
        return executed

    def _up_standalone(self) -> list[str]:
        binary = self._binary()
        if not os.path.exists(binary):
            raise AdapterError(f"hedioum-tunnel binary missing at {binary}")
        workdir = f"{appconfig.DATA_DIR}/hedioum/{self.alias}"
        os.makedirs(workdir, exist_ok=True)
        # standalone mode: config is per-workdir (non-root dev/lab layout)
        self.down_standalone()
        with open(f"{workdir}/hedioum.json", "w") as f:
            f.write(json.dumps({"role": "iran",
                                "foreign_nodes": [self._node()]},
                               indent=2))
            os.chmod(f.name, 0o600)
        logf = open(f"{workdir}/hedioum.log", "ab")
        proc = _popen(
            [binary], cwd=workdir, stdout=logf, stderr=subprocess.STDOUT,
            start_new_session=True)
        with open(f"{workdir}/hedioum.pid", "w") as f:
            f.write(str(proc.pid))
        return [f"standalone start pid={proc.pid} cwd={workdir}"]

    def up(self) -> list[str]:
        executed = []
        for path, content in self.render().items():
            if path == CONFIG_PATH and not self.cfg.get("standalone"):
                self.write_artifact(path, content, mode=0o600)
                executed.append(f"write {path} (merged node '{self.alias}')")
            elif path != CONFIG_PATH:
                self.write_artifact(path, content)
                executed.append(f"write {path}")
        if self.cfg.get("standalone"):
            executed += self._up_standalone()
        else:
            executed += self._up_systemd()
        # wait for the SOCKS ingress to accept connections
        deadline = time.time() + 15
        while time.time() < deadline:
            if self._socks_alive():
                executed.append(f"socks5 ingress 127.0.0.1:{self.socks_port} "
                                "accepting")
                break
            time.sleep(0.5)
        else:
            raise AdapterError(
                f"SOCKS5 ingress on {self.socks_port} did not come up "
                "within 15s — check hedioum logs (journalctl -u hedioum)")
        return executed

    # ---------------------------------------------------------------- down
    def _merged_without_us(self) -> str | None:
        existing = self._read_hub_config()
        if not existing:
            return None
        nodes = [n for n in (existing.get("foreign_nodes") or [])
                 if isinstance(n, dict) and n.get("alias") != self.alias]
        existing["foreign_nodes"] = nodes
        return json.dumps(existing, indent=2, ensure_ascii=False)

    def down_standalone(self) -> list[str]:
        workdir = f"{appconfig.DATA_DIR}/hedioum/{self.alias}"
        pidfile = f"{workdir}/hedioum.pid"
        done = []
        try:
            with open(pidfile) as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            done.append(f"killed standalone pid={pid}")
        except (OSError, ValueError):
            pass
        try:
            os.remove(pidfile)
        except OSError:
            pass
        return done

    def down(self) -> list[str]:
        executed = []
        if self.cfg.get("standalone"):
            executed += self.down_standalone()
        else:
            merged = self._merged_without_us()
            if merged is not None:
                self.write_artifact(CONFIG_PATH, merged, mode=0o600)
                executed.append(f"write {CONFIG_PATH} (node '{self.alias}' "
                                "removed)")
                cp = self.exec(["systemctl", "restart", "hedioum"], timeout=40)
                executed.append(f"systemctl restart hedioum "
                                f"(rc={cp.returncode})")
            else:
                executed.append("hub config absent — nothing to remove")
        return executed

    # -------------------------------------------------------------- status
    def _socks_alive(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.socks_port),
                                          timeout=1.5):
                return True
        except OSError:
            return False

    def _pid_alive(self) -> bool:
        workdir = f"{appconfig.DATA_DIR}/hedioum/{self.alias}"
        try:
            with open(f"{workdir}/hedioum.pid") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False

    def status(self) -> dict:
        socks_ok = self._socks_alive()
        if self.cfg.get("standalone"):
            svc_ok = self._pid_alive()
            detail = "standalone hub process" if svc_ok else \
                "standalone process not running"
        else:
            cp = self.exec(["systemctl", "is-active", "hedioum"], timeout=10)
            svc_ok = cp.returncode == 0 and cp.stdout.strip() == "active"
            detail = f"systemd hedioum: {cp.stdout.strip() or 'unknown'}"
        extra = {"socks_port": self.socks_port, "alias": self.alias,
                 "tun_enabled": self.routing_capable}
        return {"up": bool(svc_ok and socks_ok), "detail": detail,
                "extra": extra}

    # --------------------------------------------------------------- probe
    def _probe_cycle(self) -> dict:
        """Through-tunnel probe: SOCKS5 CONNECT handshake against
        probe_target:probe_port via the local ingress. This measures the
        REAL user path (hub -> pool -> foreign -> internet)."""
        from .. import probes
        target = self.cfg.get("probe_target") or "1.1.1.1"
        port = int(self.cfg.get("probe_port") or 443)
        s = self._settings()
        return probes.socks5_cycle(
            self.socks_port, target, port,
            count=max(2, int(s.get("probe_count", 5)) // 2),
            timeout_s=float(s.get("probe_timeout_s", 2)) + 2.0)

    def receipt(self) -> dict:
        """Activation receipt: real HTTP GET through the tunnel — proves the
        pool carries end-user traffic, and reports the exit IP the foreign
        node is presenting to the internet. Multiple providers x retries so
        one flaky provider or a fresh pool never yields a false negative."""
        from .. import probes
        providers = (("api.ipify.org", "/"), ("icanhazip.com", "/"),
                     ("ifconfig.me", "/ip"))
        attempts = 0
        for _round in range(3):
            for host, path in providers:
                attempts += 1
                body = probes.socks5_http_get(self.socks_port, host, path)
                if body and len(body) <= 64 and not body.startswith("<"):
                    return {"exit_ip": body.strip(), "through_tunnel": True,
                            "attempts": attempts, "provider": host}
            time.sleep(1.0)
        return {"exit_ip": None, "through_tunnel": False, "attempts": attempts}
