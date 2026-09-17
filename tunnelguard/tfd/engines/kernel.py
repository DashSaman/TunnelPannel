"""TunnelGuard — kernel tunnel adapters: GRE and SIT (6in4).

Both are `ip tunnel`-family L3 tunnels. Outer headers need the *public*
addresses of both endpoints; inner addresses come from tunnel.local_ip /
remote_ip.

GRE  config: local_public_ip, remote_host, ttl (64), key (optional)
SIT  config: local_public_ip, remote_host, ttl (255), v6_local, v6_remote
             (both required — SIT is an IPv6-over-IPv4 tunnel; the realistic
             replacement for the deprecated 6to4, RFC 7526).

Honest limits surfaced in precheck:
 - GRE needs ip_gre module and GRE (proto 47) not filtered upstream — the
   second one can't be verified locally and the adapter says exactly that.
 - SIT needs proto 41 end-to-end and public IPv4 on BOTH sides.
"""
from __future__ import annotations

from .base import EngineAdapter


class _KernelTunnelAdapter(EngineAdapter):
    mode = "gre"

    def _outer(self) -> list[str]:
        c = self.cfg
        return [
            "ip", "tunnel", "add", self.iface, "mode", self.mode,
            "local", c.get("local_public_ip", ""),
            "remote", c.get("remote_host") or self.t.get("remote_host") or "",
            "ttl", str(c.get("ttl", 64 if self.mode == "gre" else 255)),
        ] + (["key", str(c["key"])] if c.get("key") else [])

    def render(self) -> dict[str, str]:
        cmds = ["# ".join([self._outer()[0] + " " + " ".join(self._outer()[1:])])]
        return {"commands/{}_up.sh".format(self.iface): "\n".join(
            cmds + self._up_tail())}

    def _up_tail(self) -> list[str]:
        cmds = [f"ip addr replace {self.t.get('local_ip')}/30 dev {self.iface}"]
        if self.mode == "sit":
            c = self.cfg
            v6l = c.get("v6_local")
            v6r = c.get("v6_remote")
            if v6l and v6r:
                cmds.append(f"ip -6 addr replace {v6l}/64 dev {self.iface}")
                cmds.append(f"ip -6 route replace {v6r}/128 dev {self.iface}")
        cmds.append(f"ip link set {self.iface} mtu {self.t.get('mtu') or 1476} up")
        return cmds

    def precheck(self) -> list[str]:
        problems = []
        c = self.cfg
        if not c.get("local_public_ip"):
            problems.append("local_public_ip (outer header) not configured")
        if not (c.get("remote_host") or self.t.get("remote_host")):
            problems.append("remote public host (outer header) not configured")
        if not self.t.get("local_ip") or not self.t.get("remote_ip"):
            problems.append("inner tunnel addresses (local_ip/remote_ip) missing")
        # probe kernel module with a throwaway loopback tunnel
        probe_if = f"tf-pre-{self.mode}"
        self.exec(["ip", "link", "del", probe_if], timeout=5)
        cp = self.exec(self._outer()[:1] + [probe_if] + self._outer()[4:], timeout=10)
        if cp.returncode != 0:
            problems.append(
                f"kernel {self.mode} tunnel unavailable: "
                f"{(cp.stderr or '').strip()[:110]} (module missing?)")
        else:
            self.exec(["ip", "tunnel", "del", probe_if], timeout=5)
        if self.mode == "sit":
            if not (c.get("v6_local") and c.get("v6_remote")):
                problems.append(
                    "SIT needs v6_local and v6_remote (IPv6 inside the tunnel)")
            problems.append(
                "NOTE: proto 41 must not be filtered end-to-end — cannot be "
                "verified locally; verify with selftest on the real server")
        if self.mode == "gre":
            problems.append(
                "NOTE: GRE (IP proto 47) is NOT encrypted and may be filtered "
                "by some upstreams — verify with selftest")
        return problems

    def up(self) -> list[str]:
        self.exec(["ip", "tunnel", "del", self.iface], timeout=5)  # idempotent
        self._run_or_fail(self._outer(), f"ip tunnel add {self.mode}")
        for c in self._up_tail():
            self._run_or_fail(c.split(), f"cmd: {c}")
        return [f"ip tunnel add {self.mode} {self.iface}", *self._up_tail()]

    def down(self) -> list[str]:
        cp = self.exec(["ip", "tunnel", "del", self.iface], timeout=10)
        return [f"ip tunnel del {self.iface} "
                f"({'ok' if cp.returncode == 0 else 'already gone'})"]

    def status(self) -> dict:
        up = self._iface_exists()
        extra = self._iface_counters() if up else {}
        if up:
            cp = self.exec(["ip", "tunnel", "show"], timeout=5)
            for line in cp.stdout.splitlines():
                if line.startswith(self.iface):
                    extra["tunnel_line"] = line.strip()
                    break
        return {"up": up, "detail": "tunnel interface present" if up else "interface missing",
                "extra": extra}


class GREAdapter(_KernelTunnelAdapter):
    name = "gre"
    mode = "gre"


class SITAdapter(_KernelTunnelAdapter):
    name = "sit"
    mode = "sit"
