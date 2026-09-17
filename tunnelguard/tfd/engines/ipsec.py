"""TunnelGuard — IPsec family adapters: IKEv2/VTI (strongSwan) and L2TPv3.

IKEv2 VTI (engine "ikev2"):
  strongSwan swanctl + a kernel VTI interface. Needs UDP 500/4500 both ends.
  This is the heaviest engine to debug on real networks (NAT, port filtering,
  retransmission timers) — precheck + selftest report as much as the host
  can honestly verify; end-to-end reachability of UDP500/4500 can NOT be
  verified locally and is flagged accordingly.

L2TPv3 kernel (engine "l2tp"):
  unmanaged kernel L2TPv3 over UDP (`ip l2tp add tunnel`) — no xl2tpd/pppd.
  NOTE: this is L2TPv3 (data link over UDP 1701), NOT the old L2TPv2/ppp;
  optionally protect it with IPsec (documented, not auto-wired in v1).

Config (ikev2): local_public_ip, remote_host, local_ts, remote_ts,
  psk, ike (algos), esp (algos), vti_key
Config (l2tp):  local_public_ip, remote_host, tunnel_id, peer_tunnel_id,
  session_id, peer_session_id, udp_port
"""
from __future__ import annotations

from .base import EngineAdapter

def _swanctl_dir() -> str:
    from .. import config
    return config.SWANCTL_DIR



class IKEv2Adapter(EngineAdapter):
    name = "ikev2"

    def _conn_name(self) -> str:
        return f"tg-{self.iface}"

    # ------------------------------------------------------------- render
    def render(self) -> dict[str, str]:
        c = self.cfg
        name = self._conn_name()
        content = (
            f"{name} {{\n"
            "  version = 2\n"
            f"  local {{\n    auth = psk\n    id = {c.get('local_public_ip')}\n"
            f"    addr = {c.get('local_public_ip')}\n  }}\n"
            f"  remote {{\n    auth = psk\n"
            f"    id = {c.get('remote_host')}\n"
            f"    addr = {c.get('remote_host')}\n  }}\n"
            f"  local_ts = {c.get('local_ts', '0.0.0.0/0')}\n"
            f"  remote_ts = {c.get('remote_ts', '0.0.0.0/0')}\n"
            f"  ike = {c.get('ike', 'aes256gcm16-prfsha384-ecp384!')}\n"
            f"  esp = {c.get('esp', 'aes256gcm16-ecp384!')}\n"
            "  start_action = start\n"
            f"  if_id_in = {c.get('vti_key', 100 + int(self.t.get('id', 0) or 0))}\n"
            f"  if_id_out = {c.get('vti_key', 100 + int(self.t.get('id', 0) or 0))}\n"
            "  dpd_delay = 10s\n"
            "  dpd_timeout = 40s\n"
            "}\n"
        )
        secrets = (
            f"{name} : PSK \"{c.get('psk', '<PSK>')}\")\n".replace(")", "")
        )
        return {f"{_swanctl_dir()}/{name}.conf": content,
                f"{_swanctl_dir()}/{name}.secrets": secrets}

    # ----------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        problems = []
        if not self._which("swanctl"):
            problems.append("strongSwan swanctl not installed "
                            "(apt install strongswan-swanctl strongswan-nft)")
        else:
            cp = self.exec(["systemctl", "is-active", "strongswan-swanctl"],
                           timeout=10)
            if cp.returncode != 0:
                cp2 = self.exec(["systemctl", "is-active", "strongswan"], timeout=10)
                if cp2.returncode != 0:
                    problems.append("charon (strongSwan) service is not running")
        cp = self.exec(["ss", "-uln"], timeout=5)
        if cp.returncode == 0:
            for line in cp.stdout.splitlines():
                if ":500 " in line or ":4500 " in line:
                    other = ("existing IPsec listener found on UDP500/4500 — "
                             "verify it belongs to strongSwan")
                    problems.append(other)
                    break
        for k in ("local_public_ip", "remote_host", "psk"):
            if not self.cfg.get(k):
                problems.append(f"config key '{k}' missing")
        problems.append("NOTE: UDP500/4500 must be open end-to-end; cannot be "
                        "verified locally — run selftest on the real server")
        return problems

    # ---------------------------------------------------------------- up
    def up(self) -> list[str]:
        executed = []
        for path, content in self.render().items():
            self.write_artifact(path, content)
            executed.append(f"write {path}")
        self._run_or_fail(["swanctl", "--load-conns"], "swanctl load-conns")
        self._run_or_fail(["swanctl", "--load-creds"], "swanctl load-creds")
        self._run_or_fail(["swanctl", "--initiate", "--child", self._conn_name()],
                          "swanctl initiate", timeout=40)
        key = self.cfg.get("vti_key", 100 + int(self.t.get("id", 0) or 0))
        self.exec(["ip", "link", "del", self.iface], timeout=5)
        self._run_or_fail(
            ["ip", "link", "add", self.iface, "type", "vti",
             "local", self.cfg["local_public_ip"],
             "remote", self.cfg["remote_host"], "key", str(key)],
            "ip link add vti")
        self._run_or_fail(
            f"ip addr replace {self.t.get('local_ip')}/30 dev {self.iface}".split(),
            "vti addr")
        self._run_or_fail(
            ["ip", "link", "set", self.iface,
             "mtu", str(self.t.get("mtu") or 1436), "up"], "vti up")
        executed.append(f"vti {self.iface} up (if_id {key})")
        return executed

    # -------------------------------------------------------------- down
    def down(self) -> list[str]:
        out = []
        cp = self.exec(["swanctl", "--terminate", "--child", self._conn_name()],
                       timeout=30)
        out.append(f"swanctl terminate {self._conn_name()} (rc={cp.returncode})")
        cp = self.exec(["ip", "link", "del", self.iface], timeout=10)
        out.append(f"ip link del {self.iface} ({'ok' if cp.returncode == 0 else 'gone'})")
        return out

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        up = self._iface_exists()
        extra: dict = {}
        cp = self.exec(["swanctl", "--list-sas"], timeout=10)
        if cp.returncode == 0:
            extra["sas"] = cp.stdout.strip()[:400] or "(no SAs)"
        return {"up": up, "detail": "vti iface present" if up else "interface missing",
                "extra": extra}


class L2TPv3Adapter(EngineAdapter):
    name = "l2tp"

    # ------------------------------------------------------------- render
    def render(self) -> dict[str, str]:
        c = self.cfg
        script = "\n".join([
            "# L2TPv3 kernel tunnel (unmanaged)",
            f"ip l2tp add tunnel tunnel_id {c.get('tunnel_id', 1)} "
            f"peer_tunnel_id {c.get('peer_tunnel_id', 1)} "
            f"udp_sport {c.get('udp_port', 1701)} udp_dport {c.get('udp_port', 1701)} "
            f"encap udp local {c.get('local_public_ip')} remote {c.get('remote_host')}",
            f"ip l2tp add session tunnel_id {c.get('tunnel_id', 1)} "
            f"session_id {c.get('session_id', 1)} "
            f"peer_session_id {c.get('peer_session_id', 1)}",
            f"ip link set {self.iface} mtu {self.t.get('mtu') or 1410} up",
            f"ip addr replace {self.t.get('local_ip')}/30 dev {self.iface}",
        ])
        return {f"commands/{self.iface}_up.sh": script}

    # ----------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        problems = []
        probe = self.exec(["ip", "l2tp", "show", "tunnel"], timeout=5)
        if probe.returncode != 0:
            problems.append(f"kernel L2TPv3 unavailable: "
                            f"{(probe.stderr or '').strip()[:100]} (l2tp module?)")
        for k in ("local_public_ip", "remote_host"):
            if not self.cfg.get(k):
                problems.append(f"config key '{k}' missing")
        return problems

    # ---------------------------------------------------------------- up
    def up(self) -> list[str]:
        c = self.cfg
        self.exec(["ip", "l2tp", "del", "session", "tunnel_id",
                   str(c.get("tunnel_id", 1)), "session_id",
                   str(c.get("session_id", 1))], timeout=5)
        self.exec(["ip", "l2tp", "del", "tunnel", "tunnel_id",
                   str(c.get("tunnel_id", 1))], timeout=5)
        self._run_or_fail(
            ["ip", "l2tp", "add", "tunnel", "tunnel_id", str(c.get("tunnel_id", 1)),
             "peer_tunnel_id", str(c.get("peer_tunnel_id", 1)),
             "udp_sport", str(c.get("udp_port", 1701)),
             "udp_dport", str(c.get("udp_port", 1701)),
             "encap", "udp", "local", c["local_public_ip"],
             "remote", c["remote_host"]], "ip l2tp add tunnel")
        self._run_or_fail(
            ["ip", "l2tp", "add", "session", "tunnel_id", str(c.get("tunnel_id", 1)),
             "session_id", str(c.get("session_id", 1)),
             "peer_session_id", str(c.get("peer_session_id", 1))], "ip l2tp add session")
        self._run_or_fail(
            ["ip", "link", "set", self.iface,
             "mtu", str(self.t.get("mtu") or 1410), "up"], "l2tp link up")
        self._run_or_fail(
            f"ip addr replace {self.t.get('local_ip')}/30 dev {self.iface}".split(),
            "l2tp addr")
        return [f"L2TPv3 tunnel/session {self.iface} up"]

    # -------------------------------------------------------------- down
    def down(self) -> list[str]:
        c = self.cfg
        self.exec(["ip", "l2tp", "del", "session", "tunnel_id",
                   str(c.get("tunnel_id", 1)), "session_id",
                   str(c.get("session_id", 1))], timeout=10)
        cp = self.exec(["ip", "l2tp", "del", "tunnel", "tunnel_id",
                        str(c.get("tunnel_id", 1))], timeout=10)
        return [f"L2TPv3 tunnel {c.get('tunnel_id', 1)} "
                f"({'deleted' if cp.returncode == 0 else 'was gone'})"]

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        up = self._iface_exists()
        extra: dict = {}
        cp = self.exec(["ip", "l2tp", "show", "tunnel"], timeout=5)
        if cp.returncode == 0:
            extra["tunnels"] = cp.stdout.strip()[:300]
        return {"up": up, "detail": "l2tp iface present" if up else "interface missing",
                "extra": extra}
