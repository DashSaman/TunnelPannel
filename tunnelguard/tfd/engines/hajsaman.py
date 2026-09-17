"""TunnelGuard — HajSamanTunnel engine adapter (real, v1.2).

HajSamanTunnel (DashSaman/HajSamanTunnel v0.4) is a bash wizard that deploys
an Iran<->Foreign tunnel with this stack:

    Xray (sockopt.mark / SO_MARK)  ->  WireGuard IPv4  ->  SIT (proto 41)
    ->  Foreign server  ->  SNAT  ->  Internet

i.e. a WireGuard point-to-point /30 INSIDE a SIT (IPv6-over-IPv4, IP proto 41)
underlay, with policy routing driven by an fwmark so only Xray-marked traffic
uses the tunnel. Each slot has its own systemd service + auto-heal timer.

TunnelGuard supports BOTH operating modes:

mode="cli"  (default when the tool is installed)
  Wraps the real `hajsaman-tunnel` CLI. TunnelGuard owns NOTHING the wizard
  owns (keys, join codes, heal timers) — it starts/stops the slot and probes
  it for real by reading /etc/hajsaman-tunnel/tunnels.d/<slot>.conf:
    - ping the WireGuard peer THROUGH the WG iface (source = own WG /32,
      which the slot's `ip rule ... from <GW_WG_IP> lookup <TABLE>` maps to
      the tunnel)
    - SIT underlay ping6 as a degraded-path detail
    - exit-IP receipt via `curl --interface <WG_IP>` (the same check the
      wizard's own diagnostics uses)

mode="native" (tool not installed)
  TunnelGuard builds the same two-server stack itself: SIT underlay + wg-quick
  /30 inside it + policy rule/table + MTU. It does NOT implement the
  three-server access-WG mode or the auto-heal timers — the real wizard is
  the right tool for those; this mode exists so the engine still works from
  a clean box. Same honest limits as the upstream: the ISP still sees IP
  proto 41, its volume and PPS; if proto 41 is blocked upstream nothing can
  carry it.

Config keys (tunnel.config JSON) — cli mode:
  slot               slot name under tunnels.d (default hst-<id>)
  cli_path           default /usr/local/sbin/hajsaman-tunnel
  conf_dir           default /etc/hajsaman-tunnel/tunnels.d
  probe_target       override inner peer (autodetected from the conf)
  probe_underlay     also ping the SIT v6 peer for status detail (default on)

Config keys — native mode (mode="native"):
  role               iran|foreign (which side this box is)
  local_public_ip    this server's public IPv4 (SIT outer local)
  foreign_ipv4       peer public IPv4 (SIT outer remote)
  wg_listen_port     WireGuard UDP port inside SIT (default 51821+id)
  private_key        WireGuard private key of THIS side
  peer_public_key    WireGuard public key of the peer
  peer_endpoint      peer inner v6 ULA (autod: fd00:05a1:<id>::2 or ::1)
  psk                optional preshared key
  mark               fwmark for policy routing (default 31400+id)
  table              routing table id (default 31400+id)
  sit_mtu / wg_mtu   defaults 1480 / 1420 (upstream's safe ranges)
"""
from __future__ import annotations

import re

from .base import EngineAdapter, AdapterError
from .. import config as appconfig

CLI_DEFAULT = "/usr/local/sbin/hajsaman-tunnel"
CONF_DIR_DEFAULT = "/etc/hajsaman-tunnel/tunnels.d"

_KV_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")


def parse_slot_conf(text: str) -> dict:
    """Parse a tunnels.d/<slot>.conf file (shell KEY=value lines)."""
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _KV_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return out


class HajSamanAdapter(EngineAdapter):
    name = "hajsaman"

    # real L3 tunnel (WG inside SIT + policy routing) in both modes
    @property
    def routing_capable(self) -> bool:
        return True

    # ------------------------------------------------------------- identity
    @property
    def mode(self) -> str:
        m = str(self.cfg.get("mode") or "").lower()
        if m in ("cli", "native"):
            return m
        # auto: cli when the tool is present on the box
        import os
        cli = self.cfg.get("cli_path") or CLI_DEFAULT
        import shutil
        return "cli" if (os.path.exists(cli) or shutil.which(
            "hajsaman-tunnel")) else "native"

    @property
    def slot(self) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]", "-",
                      str(self.cfg.get("slot") or f"hst-{self.t.get('id', 0)}"))

    @property
    def conf_path(self) -> str:
        return f"{self.cfg.get('conf_dir') or CONF_DIR_DEFAULT}/{self.slot}.conf"

    # ------------------------------------------------------ slot conf cache
    def _slot_conf(self) -> dict | None:
        cp = self.exec(["cat", self.conf_path], timeout=10)
        if cp.returncode != 0:
            return None
        conf = parse_slot_conf(cp.stdout)
        return conf or None

    # --------------------------------------------------------------- render
    def render(self) -> dict[str, str]:
        if self.mode == "cli":
            conf = self._slot_conf()
            return {
                "commands/hajsaman-{slot}.txt".format(slot=self.slot):
                    "# managed slot (cli mode) — config owned by the\n"
                    "# hajsaman-tunnel wizard; TunnelGuard only starts/\n"
                    "# stops/probes it.\n"
                    f"conf: {self.conf_path}\n"
                    f"probe: ping through WG peer\n",
            }
        return self._render_native()

    def _render_native(self) -> dict[str, str]:
        c = self.cfg
        tid = int(self.t.get("id", 0) or 0)
        role = "foreign" if str(c.get("role", "iran")).startswith("fore") \
            else "iran"
        sit_if = f"sit-hst{tid}"
        wg_if = f"tf-hst{tid}"
        port = int(c.get("wg_listen_port") or 51821 + tid % 600)
        mark = int(c.get("mark") or 31400 + tid)
        table = int(c.get("table") or 31400 + tid)
        sit_mtu = int(c.get("sit_mtu") or 1480)
        wg_mtu = int(c.get("wg_mtu") or 1420)
        v6net = f"fd00:05a1:{tid:04x}::"
        if role == "iran":
            v6_local, v6_peer = f"{v6net}1/64", f"{v6net}2"
            wg_local = f"10.90.{tid % 200}.1/30"
            wg_peer_ip = f"10.90.{tid % 200}.2"
        else:
            v6_local, v6_peer = f"{v6net}2/64", f"{v6net}1"
            wg_local = f"10.90.{tid % 200}.2/30"
            wg_peer_ip = f"10.90.{tid % 200}.1"
        local_pub = c.get("local_public_ip") or ""
        foreign_pub = c.get("foreign_ipv4") or self.t.get("remote_host") or ""
        wg_conf = (
            "[Interface]\n"
            f"Address = {wg_local}\n"
            f"PrivateKey = {c.get('private_key') or 'REPLACE_ME'}\n"
            f"ListenPort = {port}\n"
            f"MTU = {wg_mtu}\n"
            + (f"Table = {table}\n" if role == "iran" else "")
            + "\n[Peer]\n"
            f"PublicKey = {c.get('peer_public_key') or 'REPLACE_ME'}\n"
            f"Endpoint = [{v6_peer}]:{port}\n"
            f"AllowedIPs = {wg_peer_ip}/32, 0.0.0.0/0\n"
            + (f"PresharedKey = {c['psk']}\n" if c.get("psk") else "")
            + ("PersistentKeepalive = 25\n" if role == "iran" else "")
        )
        up_script = (
            "#!/bin/sh\n# TunnelGuard — HajSaman-style two-server stack\n"
            "set -e\n"
            f"ip tunnel del {sit_if} 2>/dev/null || true\n"
            f"ip tunnel add {sit_if} mode sit local {local_pub} "
            f"remote {foreign_pub} ttl 255\n"
            f"ip link set {sit_if} mtu {sit_mtu} up\n"
            f"ip -6 addr replace {v6_local} dev {sit_if}\n"
            f"ip -6 route replace {v6_peer}/128 dev {sit_if}\n"
            "# let the WG-over-SIT udp packets in\n"
            f"ip6tables -C INPUT -i {sit_if} -s {v6_peer} "
            f"-p udp --dport {port} -j ACCEPT 2>/dev/null || "
            f"ip6tables -I INPUT 1 -i {sit_if} -s {v6_peer} "
            f"-p udp --dport {port} -j ACCEPT\n"
            f"wg-quick up {wg_if}\n"
            + (f"ip rule del fwmark 0x{mark:x} table {table} 2>/dev/null || true\n"
               f"ip rule add fwmark 0x{mark:x} table {table} prio 8000\n"
               f"ip route replace default dev {wg_if} table {table} "
               f"mtu {wg_mtu}\n"
               if role == "iran" else
               f"iptables -t nat -C POSTROUTING -o {wg_if} -j MASQUERADE "
               "2>/dev/null || iptables -t nat -A POSTROUTING -o "
               f"{wg_if} -j MASQUERADE\n")
        )
        down_script = (
            "#!/bin/sh\n"
            f"wg-quick down {wg_if} 2>/dev/null || true\n"
            f"ip rule del fwmark 0x{mark:x} table {table} 2>/dev/null || true\n"
            f"ip tunnel del {sit_if} 2>/dev/null || true\n"
        )
        return {
            f"/etc/wireguard/{wg_if}.conf": wg_conf,
            f"commands/hajsaman-{self.slot}-up.sh": up_script,
            f"commands/hajsaman-{self.slot}-down.sh": down_script,
        }

    # ------------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        p: list[str] = []
        if self.mode == "cli":
            cli = self.cfg.get("cli_path") or CLI_DEFAULT
            import os, shutil
            if not (os.path.exists(cli) or shutil.which("hajsaman-tunnel")):
                p.append("hajsaman-tunnel CLI not found — deploy a slot with "
                         "the wizard first (or use mode='native')")
                return p
            conf = self._slot_conf()
            if not conf:
                p.append(f"slot conf {self.conf_path} not found — create the "
                         f"slot first (`hajsaman-tunnel` menu option 1/2, "
                         "then start it once)")
                return p
            if not (conf.get("WG_IF") and (conf.get("GW_WG_IP")
                                           or conf.get("FOREIGN_WG_IP"))):
                p.append("slot conf is incomplete (WG_IF / WG IPs missing) — "
                         "rebuild the slot")
            if str(conf.get("ADMIN_STATE", "")).lower() in ("stopped", "off"):
                p.append(f"slot '{self.slot}' is intentionally stopped "
                         "(ADMIN_STATE) — start it via "
                         f"`hajsaman-tunnel start {self.slot}`")
            p.append("NOTE: the ISP sees IP proto 41 (SIT) volume/PPS — "
                     "proto-41 filtering upstream cannot be detected locally")
            return p
        # native
        import os, shutil
        for b in ("ip", "wg", "wg-quick"):
            if not shutil.which(b):
                p.append(f"required binary '{b}' missing (apt install "
                         "wireguard-tools iproute2)")
        c = self.cfg
        if not c.get("local_public_ip"):
            p.append("local_public_ip (SIT outer header) not configured")
        if not (c.get("foreign_ipv4") or self.t.get("remote_host")):
            p.append("foreign_ipv4 (SIT outer remote) not configured")
        if not c.get("private_key"):
            p.append("private_key missing (this side's WireGuard private key)")
        if not c.get("peer_public_key"):
            p.append("peer_public_key missing (peer's WireGuard public key)")
        p.append("NOTE: native mode builds the two-server SIT+WG stack "
                 "directly; three-server mode & auto-heal stay in the real "
                 "hajsaman-tunnel wizard")
        p.append("NOTE: proto 41 must not be filtered end-to-end — verify "
                 "with selftest on the real server")
        return p

    # ------------------------------------------------------------------ up
    def up(self) -> list[str]:
        executed: list[str] = []
        if self.mode == "cli":
            cli = self.cfg.get("cli_path") or CLI_DEFAULT
            cp = self.exec([cli, "start", self.slot], timeout=90)
            if cp.returncode != 0:
                raise AdapterError(
                    f"hajsaman-tunnel start {self.slot} failed "
                    f"(rc={cp.returncode}): "
                    f"{(cp.stderr or cp.stdout).strip()[:200]}")
            executed.append(f"hajsaman-tunnel start {self.slot} (rc=0)")
            return executed
        # native: write artifacts, then run the up script
        artifacts = self._render_native()
        up_key = "commands/hajsaman-" + self.slot + "-up.sh"
        script_path = f"{appconfig.DATA_DIR}/{up_key}"
        for path, content in artifacts.items():
            if path.startswith("commands/"):
                continue
            self.write_artifact(path, content, mode=0o600)
            executed.append(f"write {path}")
        self.write_artifact(script_path, artifacts[up_key], mode=0o700)
        cp = self.exec(["sh", script_path], timeout=60)
        if cp.returncode != 0:
            raise AdapterError(
                f"native up script failed (rc={cp.returncode}): "
                f"{(cp.stderr or cp.stdout).strip()[:200]}")
        executed.append(f"native stack up (SIT+WG, slot {self.slot})")
        return executed

    # ---------------------------------------------------------------- down
    def down(self) -> list[str]:
        if self.mode == "cli":
            cli = self.cfg.get("cli_path") or CLI_DEFAULT
            cp = self.exec([cli, "stop", self.slot], timeout=90)
            return [f"hajsaman-tunnel stop {self.slot} (rc={cp.returncode})"]
        executed: list[str] = []
        artifacts = self._render_native()
        down_key = "commands/hajsaman-" + self.slot + "-down.sh"
        script_path = f"{appconfig.DATA_DIR}/{down_key}"
        self.write_artifact(script_path, artifacts[down_key], mode=0o700)
        cp = self.exec(["sh", script_path], timeout=60)
        executed.append(f"native stack down (rc={cp.returncode})")
        return executed

    # -------------------------------------------------------------- status
    def status(self) -> dict:
        if self.mode == "cli":
            cli = self.cfg.get("cli_path") or CLI_DEFAULT
            cp = self.exec([cli, "status"], timeout=30)
            text = cp.stdout or ""
            slot_running = self.slot in text and (
                f"{self.slot}" in text)
            conf = self._slot_conf() or {}
            extra = {"mode": "cli", "slot": self.slot,
                     "role": conf.get("ROLE"),
                     "wg_if": conf.get("WG_IF"),
                     "admin_state": conf.get("ADMIN_STATE")}
            if conf.get("WG_IF"):
                cp2 = self.exec(["ip", "-o", "link", "show",
                                 "dev", conf["WG_IF"]], timeout=5)
                iface_up = cp2.returncode == 0
                extra["wg_iface_present"] = iface_up
            else:
                iface_up = False
            up = bool(slot_running or iface_up)
            return {"up": up, "detail":
                    f"slot {self.slot}: "
                    f"{'in status output' if slot_running else 'not listed'}"
                    f"{', WG iface present' if iface_up else ''}",
                    "extra": extra}
        # native
        tid = int(self.t.get("id", 0) or 0)
        wg_if = f"tf-hst{tid}"
        cp = self.exec(["ip", "-o", "link", "show", "dev", wg_if], timeout=5)
        up = cp.returncode == 0
        extra = {"mode": "native", "wg_if": wg_if}
        if up:
            counters = self._iface_counters()
            if counters:
                extra.update(counters)
        return {"up": up,
                "detail": "native WG iface present" if up
                else "native WG iface missing",
                "extra": extra}

    # --------------------------------------------------------------- probe
    def _wg_probe_pair(self, conf: dict) -> tuple[str | None, str | None]:
        """(peer inner IP to ping, own WG IP as source)."""
        role = str(conf.get("ROLE") or "").lower()
        if role.startswith("fore"):          # this box is the foreign
            return conf.get("GW_WG_IP"), conf.get("FOREIGN_WG_IP")
        return conf.get("FOREIGN_WG_IP"), conf.get("GW_WG_IP")

    def _probe_cycle(self) -> dict:
        from .. import probes
        conf = self._slot_conf()
        if not conf:
            return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                    "ok": False, "method": "icmp",
                    "detail": f"slot conf {self.conf_path} unreadable"}
        target, source = self._wg_probe_pair(conf)
        override = self.cfg.get("probe_target")
        if override:
            target, source = override, source
        s = self._settings()
        if target and source:
            res = probes.ping_cycle(target, int(s.get("probe_count", 5)),
                                    float(s.get("probe_timeout_s", 2)),
                                    source=source)
        elif target:
            res = probes.ping_cycle(target, int(s.get("probe_count", 5)),
                                    float(s.get("probe_timeout_s", 2)))
        else:
            return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                    "ok": False, "method": "icmp",
                    "detail": "no WG inner IP in slot conf"}
        if not res["ok"] and self.cfg.get("probe_underlay", True) \
                and conf.get("SIT_IF"):
            # degraded path: WG down but underlay alive?
            v6_peer = (conf.get("FOREIGN_V6")
                       if not str(conf.get("ROLE") or "").startswith("fore")
                       else conf.get("GW_V6"))
            underlay = None
            if v6_peer:
                cp = self.exec(["ping", "-6", "-I", conf["SIT_IF"],
                                "-c", "2", "-W", "2", v6_peer], timeout=15)
                underlay = cp.returncode == 0
            res = {**res, "detail":
                   (f"WG dead; SIT underlay {'ALIVE' if underlay else 'dead'}"
                    f" ({conf.get('SIT_IF')})")}
        return res

    def receipt(self) -> dict:
        """Exit-IP receipt exactly like the wizard's own diagnostics:
        curl --interface <WG_IP> https://api.ipify.org — a real end-to-end
        proof that marked traffic egresses via the foreign server."""
        import json as _json
        conf = self._slot_conf()
        if not conf:
            return {"exit_ip": None, "through_tunnel": False, "attempts": 0,
                    "detail": "slot conf unreadable"}
        _target, source = self._wg_probe_pair(conf)
        if not source:
            return {"exit_ip": None, "through_tunnel": False, "attempts": 0,
                    "detail": "no WG IP in slot conf"}
        providers = ("api.ipify.org", "icanhazip.com", "ifconfig.me")
        attempts = 0
        for host in providers:
            attempts += 1
            cp = self.exec(["curl", "-4fsS", "--interface", source,
                            "--connect-timeout", "5", "--max-time", "10",
                            f"https://{host}"], timeout=20)
            body = (cp.stdout or "").strip()
            if cp.returncode == 0 and body and len(body) <= 64:
                return {"exit_ip": body, "through_tunnel": True,
                        "attempts": attempts, "provider": host,
                        "via": f"curl --interface {source}"}
        return {"exit_ip": None, "through_tunnel": False, "attempts": attempts}
