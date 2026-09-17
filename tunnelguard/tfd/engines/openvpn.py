"""TunnelGuard — OpenVPN engine adapter (static-key point-to-point TUN).

Scope decision (honest): v1 uses OpenVPN *static key* mode (tls-client/server
off). It is the simplest reliable server-to-server tunnel: one symmetric
`secret` file on both ends, UDP transport, AES-256-GCM. No PKI ceremony.
Limitation: symmetric secret (both ends identical) — treat that file as
highly sensitive; rotate by regenerating on both ends.

Config keys: remote_host, port (1194), secret (pre-shared key content or
'generate'), proto (udp4), local_ip, remote_ip, fragment/mssfix optional.
"""
from __future__ import annotations

from .base import EngineAdapter

def _conf_dir() -> str:
    from .. import config
    return f"{config.ETC_DIR}/openvpn"

CONF_DIR = None  # lazy; use _conf_dir()


class OpenVPNAdapter(EngineAdapter):
    name = "openvpn"

    # ------------------------------------------------------------ render
    def render(self) -> dict[str, str]:
        c = self.cfg
        port = int(c.get("port", 1194))
        conf = (
            "dev-type tun\n"
            f"dev {self.iface}\n"
            "proto udp4\n"
            f"local 0.0.0.0\n"
            f"lport {port}\n"
            f"remote {c.get('remote_host') or self.t.get('remote_host') or '<REMOTE_PUBLIC>'}\n"
            f"rport {port}\n"
            "ifconfig {lip} {rip}\n"
            "secret {base}/{iface}.secret\n"
            "cipher AES-256-GCM\n"
            "data-ciphers AES-256-GCM\n"
            "auth SHA256\n"
            "keepalive 10 60\n"
            "ping-timer-rem\n"
            "persist-tun\n"
            "persist-key\n"
            "verb 3\n"
            "status {base}/{iface}.status 5\n"
        )
        content = conf.format(lip=self.t.get("local_ip"), rip=self.t.get("remote_ip"),
                              base=CONF_DIR, iface=self.iface)
        secret = c.get("secret") or "<RUN  openvpn --genkey secret %s/%s.secret  ON BOTH ENDS >" % (
            CONF_DIR, self.iface)
        return {f"{_conf_dir()}/{self.iface}.conf": content,
                f"{_conf_dir()}/{self.iface}.secret": secret}

    # ---------------------------------------------------------- precheck
    def precheck(self) -> list[str]:
        problems = []
        ov = self._which("openvpn")
        if not ov:
            problems.append("openvpn binary not installed (apt install openvpn)")
        else:
            cp = self.exec(["cat", "/dev/net/tun"], timeout=5)
            if cp.returncode != 0 and "File descriptor in bad state" not in cp.stderr:
                # 'bad state' just means tun char device exists but unused — fine
                try:
                    with open("/dev/net/tun", "rb"):
                        pass
                except OSError as e:
                    problems.append(f"/dev/net/tun unavailable: {e} "
                                    "(needed for any TUN-based engine)")
        if not (self.t.get("local_ip") and self.t.get("remote_ip")):
            problems.append("inner tunnel addresses (local_ip/remote_ip) missing")
        if not (self.cfg.get("remote_host") or self.t.get("remote_host")):
            problems.append("remote public host missing")
        return problems

    # ---------------------------------------------------------------- up
    def up(self) -> list[str]:
        import os
        executed = []
        os.makedirs(CONF_DIR, exist_ok=True)
        for path, content in self.render().items():
            if path.endswith(".secret") and self.cfg.get("secret"):
                self.write_artifact(path, content)
                executed.append(f"write {path}")
            elif path.endswith(".conf"):
                self.write_artifact(path, content)
                executed.append(f"write {path}")
        if not self.cfg.get("secret"):
            self._run_or_fail(
                ["openvpn", "--genkey", "secret", f"{_conf_dir()}/{self.iface}.secret"],
                "generate static key")
            executed.append(f"generate {_conf_dir()}/{self.iface}.secret "
                            "(COPY THIS FILE TO THE PEER!)")
        self.exec(["pkill", "-f", f"tunnelguard-{self.iface}"], timeout=5)
        self._run_or_fail(
            ["openvpn", "--daemon", f"--config", f"{_conf_dir()}/{self.iface}.conf",
             "--writepid", f"/run/tunnelguard-{self.iface}.pid",
             "--log", f"/var/log/tunnelguard-{self.iface}.log"],
            "openvpn start", timeout=20)
        executed.append(f"openvpn --daemon --config {_conf_dir()}/{self.iface}.conf")
        return executed

    # -------------------------------------------------------------- down
    def down(self) -> list[str]:
        cp = self.exec(["pkill", "-f", f"--config {_conf_dir()}/{self.iface}.conf"],
                       timeout=10)
        self.exec(["rm", "-f", f"/run/tunnelguard-{self.iface}.pid"], timeout=5)
        return [f"pkill openvpn({self.iface}) "
                f"({'signalled' if cp.returncode == 0 else 'not running'})"]

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        import os
        up = self._iface_exists()
        extra: dict = {}
        try:
            with open(f"/run/tunnelguard-{self.iface}.pid") as f:
                pid = f.read().strip()
                extra["pid"] = int(pid) if pid.isdigit() else None
        except OSError:
            extra["pid"] = None
        try:
            with open(f"{_conf_dir()}/{self.iface}.status") as f:
                for line in f:
                    if line.startswith("TUN/TAP read bytes"):
                        continue
                    if line and "," in line:
                        k, v = line.split(",", 1)
                        extra.setdefault("status", {})[k.strip()] = v.strip()
        except OSError:
            pass
        return {"up": up, "detail": "tun iface present" if up else "interface missing",
                "extra": extra}
