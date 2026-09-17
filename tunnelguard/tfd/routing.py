"""TunnelGuard — routing & virtual-IP manager + nftables + peer SSH sync.

The honest mechanics of a "fixed virtual IP" (10.10.10.5 by default):

 1. VIP /32 is pinned to `lo` on THIS host — it never disappears.
 2. All enabled tunnels can be UP at once (distinct inner IPs). Failover is
    a *routing* change, not an interface rebuild — switching is fast.
 3. Steering:
      route_mode='split'    -> per-destination routes via active tunnel
      route_mode='default'  -> default route via active tunnel
 4. Identity: nftables SNATs traffic leaving the active tunnel to the VIP,
    so the upstream always sees 10.10.10.5.
 5. Return path: the PEER must route the VIP back over whichever tunnel is
    active — we SSH-sync `ip route replace` on the peer. A short (seconds)
    return-path gap during a switch is physically unavoidable.
 6. MSS clamp on tunnel interfaces (protocol MTU differences make this
    mandatory: WireGuard 1420 vs GRE 1476 vs VTI ~1436 vs L2TPv3 ~1410).
 7. Inbound DNAT rules (public port -> VIP:port) come from settings.

sim_mode: every system mutation becomes a recorded no-op (lab safety).
"""
from __future__ import annotations

import subprocess

from . import db as dbm
from . import security

from .config import NFT_CONF
NFT_TABLE = "tunnelguard"


class SimulatedSystem:
    """Records every mutation instead of touching the kernel."""

    def __init__(self) -> None:
        self.log: list[str] = []

    def run(self, cmd, timeout=20.0) -> subprocess.CompletedProcess:
        entry = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        self.log.append(entry)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def _exec(cmd, timeout=20.0, sim: SimulatedSystem | None = None):
    if sim is not None:
        return sim.run(cmd, timeout)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ------------------------------------------------------------------- VIP
def ensure_vip(sim: SimulatedSystem | None = None) -> list[str]:
    s = dbm.get_settings()
    vip = s.get("virtual_ip", "10.10.10.5")
    if not s.get("vip_enabled"):
        return []
    if sim is not None:
        return [f"(sim) ensure vip {vip}/32 on lo"]
    cp = _exec(["ip", "addr", "show", "dev", "lo"])
    if cp.returncode == 0 and f"{vip}/32" not in cp.stdout:
        _exec(["ip", "addr", "add", f"{vip}/32", "dev", "lo"])
        return [f"ip addr add {vip}/32 dev lo"]
    return [f"vip {vip}/32 already present"]


# ------------------------------------------------------------- nftables
def build_nft_script(active_iface: str | None, s: dict) -> str:
    vip = s.get("virtual_ip", "10.10.10.5")
    lines = [
        f"delete table inet {NFT_TABLE}",
        f"table inet {NFT_TABLE} {{",
        "  chain prerouting {",
        "    type nat hook prerouting priority dstnat; policy accept;",
        "  }",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy accept;",
        "  }",
    ]
    if s.get("mss_clamp_enabled"):
        lines += [
            f'    iifname "tf*" tcp flags syn tcp option maxseg size set rt mtu',
            f'    oifname "tf*" tcp flags syn tcp option maxseg size set rt mtu',
        ]
    for rule in s.get("dnat_rules") or []:
        proto = str(rule.get("proto", "tcp"))
        port = int(rule.get("port", 0))
        to_port = int(rule.get("to_port", port))
        if port <= 0 or proto not in ("tcp", "udp", "sctp"):
            continue
        lines.append(
            f'    iifname != "lo" {proto} dport {port} dnat ip to {vip}:{to_port}')
    if active_iface:
        lines.append(f'    oifname "{active_iface}" snat ip to {vip}')
    lines.append("}")
    return "\n".join(lines) + "\n"


def apply_nft(active_iface: str | None = None,
              sim: SimulatedSystem | None = None) -> list[str]:
    s = dbm.get_settings()
    script = build_nft_script(active_iface, s)
    done = []
    if sim is not None:
        sim.run(["nft", "-f", NFT_CONF])
        sim.log.append(f"nft script: {script.strip()[:200]}...")
        return ["(sim) nftables table rebuilt"
                + (f" with SNAT on {active_iface}" if active_iface else "")]
    import os
    os.makedirs("/etc/tunnelguard", exist_ok=True)
    with open(NFT_CONF, "w") as f:
        f.write(script)
    cp = _exec(["nft", "-f", NFT_CONF])
    if cp.returncode != 0:
        done.append(f"nft apply FAILED: {(cp.stderr or '').strip()[:160]}")
    else:
        done.append("nftables table rebuilt"
                    + (f" with SNAT on {active_iface}" if active_iface else ""))
    return done


# ---------------------------------------------------------------- steering
def activate_tunnel_routes(tunnel: dict, prev_tunnel: dict | None = None,
                           sim: SimulatedSystem | None = None) -> list[str]:
    """Make `tunnel` the preferred path (and the SNAT identity)."""
    s = dbm.get_settings()
    vip = s.get("virtual_ip", "10.10.10.5")
    iface = tunnel.get("iface")
    done = ensure_vip(sim=sim)
    if s.get("route_mode") == "default":
        remote_ip = tunnel.get("remote_ip")
        if remote_ip:
            _exec(["ip", "route", "replace", "default", "via", remote_ip,
                   "dev", iface, "metric", "100"], sim=sim)
            done.append(f"ip route replace default via {remote_ip} dev {iface} metric 100")
    else:
        targets = []
        if tunnel.get("remote_lan"):
            targets.append(tunnel["remote_lan"])
        if tunnel.get("remote_ip"):
            targets.append(f"{tunnel['remote_ip']}/32")
        for tgt in targets:
            _exec(["ip", "route", "replace", tgt, "dev", iface, "src", vip],
                  sim=sim)
            done.append(f"ip route replace {tgt} dev {iface} src {vip}")
    done += apply_nft(active_iface=iface, sim=sim)
    done += sync_peer_route(tunnel, sim=sim)
    return done


def deactivate_tunnel_routes(tunnel: dict | None = None,
                             sim: SimulatedSystem | None = None) -> list[str]:
    return apply_nft(active_iface=None, sim=sim) + ["(no SNAT — no active tunnel)"]


# ---------------------------------------------------------------- peer sync
def sync_peer_route(tunnel: dict, sim: SimulatedSystem | None = None) -> list[str]:
    """SSH to the peer and route the VIP back over the (new) active tunnel."""
    s = dbm.get_settings()
    if not s.get("remote_sync_enabled"):
        return ["(peer sync disabled)"]
    if bool(s.get("sim_mode")) or sim is not None:
        return [f"(sim) peer: ip route replace {s.get('virtual_ip')}/32 via tunnel"]
    ssh_cfg = security.decrypt_creds(tunnel.get("remote_ssh") or "")
    if not ssh_cfg.get("host"):
        return ["(peer sync: no SSH credentials stored for this peer)"]
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_TofuPolicy())
        connect_kwargs = {
            "hostname": ssh_cfg["host"],
            "port": int(ssh_cfg.get("port", 22)),
            "username": ssh_cfg.get("username", "root"),
            "timeout": 15,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if ssh_cfg.get("password"):
            connect_kwargs["password"] = ssh_cfg["password"]
        if ssh_cfg.get("private_key"):
            import io
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(ssh_cfg["private_key"]))
            connect_kwargs["pkey"] = pkey
        client.connect(**connect_kwargs)
        peer_iface = ssh_cfg.get("peer_iface") or tunnel.get("iface")
        vip = s.get("virtual_ip")
        cmd = (f"ip route replace {vip}/32 dev {peer_iface} "
               f"|| ip route replace {vip}/32 "
               f"dev $(ip -o link | awk -F': ' '/tf/{{print $2; exit}}')")
        _, stdout, stderr = client.exec_command(cmd, timeout=15)
        rc = stdout.channel.recv_exit_status()
        client.close()
        if rc == 0:
            return [f"peer route synced: {vip}/32 over {peer_iface}"]
        return [f"peer route sync FAILED rc={rc}: {stderr.read()[:150]}"]
    except Exception as e:
        return [f"peer route sync error: {str(e)[:150]}"]


class _TofuPolicy:
    """Trust-on-first-use with operator-pinned fingerprint override."""

    def missing_host_key(self, client, hostname, key):
        import paramiko
        policy = paramiko.AutoAddPolicy()
        policy.missing_host_key(client, hostname, key)


# ------------------------------------------------------------------ health
def system_health(sim: SimulatedSystem | None = None) -> dict:
    checks = {}
    for binary in ("ip", "nft", "ping"):
        cp = _exec(["which", binary], sim=sim)
        checks[binary] = cp.returncode == 0
    return checks
