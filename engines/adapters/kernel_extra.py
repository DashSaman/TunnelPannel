"""Remaining kernel/VPN engine adapters (P5 U3).

Command shapes follow the proven Gen2 netns harness (mtf_kernel.sh) and
Gen1 executor kernel family: ip tunnel/ip link creation, openvpn static
key tunnels, strongSwan swanctl for IPsec. All probes are traffic-based.
"""
from __future__ import annotations

from engines.adapters import register_adapter
from engines.adapters.kernel import CommandPlanAdapter, FakeExecutor  # noqa: F401


class IpTunnelBase(CommandPlanAdapter):
    """Generic ip-tunnel lifecycle: create → addr → up; probe ping; delete."""
    MODE = ""                      # ip tunnel mode ("" => ip link type X)
    LINK_TYPE = ""                 # ip link type (mutually exclusive with MODE)
    MTU = 1476

    def _create_cmd(self, iface: str, remote: str, local: str) -> str:
        if self.MODE:
            return f"ip tunnel add {iface} mode {self.MODE} remote {remote} local {local} ttl 64"
        return (f"ip link add {iface} type {self.LINK_TYPE} remote {remote} local {local}")

    def detect(self) -> bool:
        mod = {"gre": "ip_gre", "gretap": "ip_gre", "ipip": "ipip",
               "sit": "sit", "vti": "vti", "vxlan": "vxlan"}.get(self.engine_id, "")
        rc, _ = self.executor.run(f"modprobe {mod} 2>/dev/null; ls /sys/module/{mod}")
        return rc == 0

    def inventory(self) -> dict:
        kind = self.LINK_TYPE or self.MODE
        _, out = self.executor.run(f"ip -d link show type {kind} 2>/dev/null || "
                                   f"ip tunnel show 2>/dev/null | grep -w {kind}")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append(f"{self.engine_id} kernel support missing")
        if not (self.node_b or {}).get("host"):
            problems.append("no remote peer host")
        return problems

    def commands(self) -> list[tuple[str, str]]:
        p = self.params
        iface = p["interface"]
        remote = self.node_b["host"]
        local = p.get("local_ip", "")
        create = self._create_cmd(iface, remote, local)
        if self.LINK_TYPE == "vxlan":
            create = (f"ip link add {iface} type vxlan id {p.get('vni', 100)} "
                      f"remote {remote} dstport {p.get('dstport', 4789)}")
        return [
            ("create tunnel", create),
            ("assign address", f"ip addr add {p['inner_ip_a']} dev {iface}"),
            ("bring up", f"ip link set {iface} up mtu {p.get('mtu', self.MTU)}"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        iface = self.params["interface"]
        if self.MODE or self.LINK_TYPE == "gretap":
            if self.engine_id in ("gre", "gretap", "ipip", "sit", "vti"):
                return [("delete tunnel", f"ip tunnel del {iface}")]
        return [("delete link", f"ip link del {iface}")]

    def probe_commands(self) -> list[str]:
        return [f"ping -c 3 -W 2 -I {self.params['interface']} {self.params['probe_target']}"]


@register_adapter
class GretapAdapter(IpTunnelBase):
    engine_id, profile_id, LINK_TYPE, MTU = "gretap", "default", "gretap", 1462


@register_adapter
class GretapIp6Adapter(GretapAdapter):
    profile_id = "ip6"
    LINK_TYPE = "ip6gretap"

    def commands(self) -> list[tuple[str, str]]:
        cmds = super().commands()
        cmds[0] = ("create tunnel",
                   f"ip link add {self.params['interface']} type ip6gretap "
                   f"remote {self.node_b['host']} local {self.params.get('local_ip', '::')}")
        return cmds


@register_adapter
class IpipAdapter(IpTunnelBase):
    engine_id, profile_id, MODE, MTU = "ipip", "default", "ipip", 1480


@register_adapter
class SitAdapter(IpTunnelBase):
    engine_id, profile_id, MODE, MTU = "sit", "default", "sit", 1480

    def probe_commands(self) -> list[str]:
        return [f"ping -6 -c 3 -W 2 -I {self.params['interface']} {self.params['probe_target']}"]


@register_adapter
class VxlanAdapter(IpTunnelBase):
    engine_id, profile_id, LINK_TYPE, MTU = "vxlan", "default", "vxlan", 1450


@register_adapter
class VtiAdapter(IpTunnelBase):
    engine_id, profile_id, MODE, MTU = "vti", "default", "vti", 1430

    def _create_cmd(self, iface, remote, local):
        return (f"ip tunnel add {iface} mode {self.MODE} remote {remote} local {local} "
                f"key {self.params.get('vti_key', 42)}")


@register_adapter
class Vti6Adapter(VtiAdapter):
    profile_id = "v6"
    MODE = "vti6"


@register_adapter
class OpenVpnAdapter(CommandPlanAdapter):
    engine_id, profile_id = "openvpn", "default"
    MTU = 1400

    def detect(self) -> bool:
        rc, _ = self.executor.run("command -v openvpn && ls /sys/module/tun")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("openvpn --version 2>&1 | head -1")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("openvpn binary or tun module missing")
        if not (self.node_b or {}).get("host"):
            problems.append("no remote peer host")
        return problems

    def _conf(self) -> str:
        p = self.params
        return f"""dev {p['interface']}
dev-type tun
proto {p.get('proto', 'udp')}
remote {self.node_b['host']} {p['port']}
ifconfig {p['inner_ip_a'].split('/')[0]} {p['inner_ip_b']}
secret {p.get('key_path', '/etc/tunnelpannel/openvpn-static.key')}
cipher AES-256-GCM
tun-mtu {p.get('mtu', self.MTU)}
keepalive 5 30
"""

    def commands(self) -> list[tuple[str, str]]:
        p = self.params
        conf = f"/etc/tunnelpannel/openvpn-{p['interface']}.conf"
        return [
            ("generate static key",
             f"openvpn --genkey secret {p.get('key_path', '/etc/tunnelpannel/openvpn-static.key')}"),
            ("write config", f"cat > {conf} <<'TPCONF'\n{self._conf()}TPCONF"),
            ("start", f"nohup openvpn --config {conf} --daemon "
                      f"--writepid /run/tunnelpannel/openvpn-{p['interface']}.pid"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        iface = self.params["interface"]
        return [
            ("stop", f"kill $(cat /run/tunnelpannel/openvpn-{iface}.pid 2>/dev/null) 2>/dev/null; "
                     f"rm -f /run/tunnelpannel/openvpn-{iface}.pid"),
            ("remove config", f"rm -f /etc/tunnelpannel/openvpn-{iface}.conf "
                              f"{self.params.get('key_path', '/etc/tunnelpannel/openvpn-static.key')}"),
        ]

    def probe_commands(self) -> list[str]:
        return [f"ping -c 3 -W 2 -I {self.params['interface']} {self.params['probe_target']}"]


@register_adapter
class IpsecAdapter(CommandPlanAdapter):
    """strongSwan route-based IKEv2 (profile ikev2) / L2TP (profile l2tp).
    PARTIAL: config fidelity distilled from the Gen1 executor's swanctl
    templates; real-pair verification blocked until P14."""
    engine_id = "ipsec"
    profile_id = "ikev2"

    def detect(self) -> bool:
        rc, _ = self.executor.run("command -v swanctl && ls /sys/module/xfrm")
        return rc == 0

    def inventory(self) -> dict:
        _, out = self.executor.run("swanctl --version 2>&1 | head -1; ip xfrm state count")
        return {"raw": out.strip()}

    def precheck(self) -> list[str]:
        problems = []
        if not self.detect():
            problems.append("strongSwan (swanctl) or xfrm missing")
        if not (self.node_b or {}).get("host"):
            problems.append("no remote peer host")
        return problems

    def _swanctl_conf(self) -> str:
        p = self.params
        remote = self.node_b["host"]
        psk = p.get("psk", "REPLACE_ME_PSK")          # redacted in plans
        return """connections {
  tp-%(profile)s {
    local_addrs  = %(local)s
    remote_addrs = %(remote)s
    version = 2
    local { auth = psk psk = %(psk)s }
    remote { auth = psk }
    children {
      tp-child {
        mode = tunnel
        start_action = start
        remote_ts = %(rts)s
        local_ts  = %(lts)s
      }
    }
  }
}
""" % {"profile": self.profile_id,
            "local": p.get("local_ip", "%any"),
            "remote": remote, "psk": psk,
            "rts": p.get("remote_ts", "0.0.0.0/0"),
            "lts": p.get("local_ts", "0.0.0.0/0")}

    def commands(self) -> list[tuple[str, str]]:
        conf = "/etc/tunnelpannel/swanctl-tp.conf"
        return [
            ("write swanctl conf", f"cat > {conf} <<'TPCONF'\n{self._swanctl_conf()}TPCONF"),
            ("load + start", f"swanctl --load-all --file {conf} && swanctl --initiate "
                             f"--child tp-child"),
        ]

    def rollback_commands(self) -> list[tuple[str, str]]:
        return [
            ("terminate", "swanctl --terminate --child tp-child 2>/dev/null; true"),
            ("remove conf", "rm -f /etc/tunnelpannel/swanctl-tp.conf"),
        ]

    def probe_commands(self) -> list[str]:
        return [f"swanctl --list-sas 2>/dev/null | grep -q 'ESTABLISHED' && "
                f"ping -c 3 -W 2 {self.params['probe_target']}"]

    def redacted_params(self) -> dict:
        out = dict(self.params)
        if "psk" in out:
            out["psk"] = "***REDACTED***"
        return out


@register_adapter
class L2tpAdapter(IpsecAdapter):
    profile_id = "l2tp"

    def _swanctl_conf(self) -> str:
        base = super()._swanctl_conf()
        return base + "\n# L2TP profile: xl2tpd layer rides this IPsec SA (Gen1 parity)\n"
