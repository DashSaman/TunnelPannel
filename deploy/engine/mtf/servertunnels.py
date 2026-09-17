#!/usr/bin/env python3
"""MTF server-tunnels engine — scan tunnels on servers + persistent install.

Scan:  SSH to each server, detect kernel tunnels / wireguard / userspace
       processes / systemd units / listeners -> data/server_tunnels.json
       (credentials are NEVER stored).
Install: tick methods in the panel -> real persistent tunnels between two
       sides (systemd units on remote hosts, supervisor scripts inside the
       panel container) -> data/installed_tunnels.json
"""
import json
import os
import re
import secrets
import subprocess
import threading
import time

import paramiko

from . import state
from . import st_profiles as P

BASE = "/opt/multitunnel"
DATA = f"{BASE}/data"
BIN = f"{BASE}/bin"
PDIR = P.PDIR
SCAN_FILE = f"{DATA}/server_tunnels.json"
INST_FILE = f"{DATA}/installed_tunnels.json"
LOCAL_ID = "panel-local"

SCAN_JOB = {"running": False, "phase": "", "progress": "", "ts": None, "err": ""}
JOB = {"running": False, "target": None, "current": None, "done": 0, "total": 0,
       "ok": 0, "partial": 0, "fail": 0, "logs": [], "err": "", "ts": None}

_lock = threading.Lock()
_job_lock = threading.Lock()

SCAN_SCRIPT = r"""
echo "===K==="
ip -o link show 2>/dev/null | grep -Ei 'gre|sit|ipip|tunl|vxlan|wg[0-9]|erspan|vti|xfrm|tun[0-9]' || true
echo "===W==="
wg show all 2>/dev/null || true
echo "===P==="
ps -eo pid,etime,args --no-headers 2>/dev/null | grep -Ei 'gost|chisel|xray|v2ray|sing-box|singbox|frps|frpc|rathole|wstunnel|hysteria|tuic|waterwall|paqet|hedioum|openvpn|charon|pluto|strongswan|xl2tpd|autossh|ss-local|sslocal|trojan|naive|anytls|mtf-|shadowsocks' | grep -v 'grep -Ei' || true
echo "===S==="
systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null | grep -Ei 'wg-quick|wireguard|mtf|tunnel|gost|chisel|xray|v2ray|sing-box|frp|rathole|wstunnel|hysteria|tuic|openvpn|strongswan|ipsec|l2tp|shadowsocks|trojan|naive|anytls|x-ui|3x-ui|s-ui' || true
echo "===L==="
ss -tulnp 2>/dev/null | head -60 || true
echo "===END==="
"""

TOOL_PATTERNS = [
    ("gost", "GOST"), ("chisel", "CHISEL"), ("xray", "XRAY"), ("v2ray", "V2RAY"),
    ("sing-box", "SING-BOX"), ("singbox", "SING-BOX"), ("frps", "FRP-SERVER"),
    ("frpc", "FRP-CLIENT"), ("rathole", "RATHOLE"), ("wstunnel", "WSTUNNEL"),
    ("hysteria", "HYSTERIA"), ("tuic", "TUIC"), ("waterwall", "WATERWALL"),
    ("paqet", "PAQET"), ("hedioum", "HEDIOUM"), ("openvpn", "OPENVPN"),
    ("charon", "STRONGSWAN"), ("pluto", "STRONGSWAN"), ("strongswan", "STRONGSWAN"),
    ("xl2tpd", "L2TP"), ("autossh", "AUTOSSH"), ("ss-local", "SHADOWSOCKS"),
    ("sslocal", "SHADOWSOCKS"), ("trojan", "TROJAN"), ("anytls", "ANYTLS"),
    ("shadowsocks", "SHADOWSOCKS"), ("ssh ", "SSH"),
]


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# ------------------------------------------------------------------ sides
class Side:
    """One execution target: the local panel container or a remote SSH host."""

    def __init__(self, spec: dict):
        self.local = bool(spec.get("local")) or spec.get("id") == LOCAL_ID
        self.name = spec.get("name") or (LOCAL_ID if self.local else spec.get("host", "?"))
        self.host = LOCAL_ID if self.local else (spec.get("host") or "")
        self.ssh_port = int(spec.get("ssh_port") or 22)
        self.username = spec.get("username") or "root"
        self.password = spec.get("password") or ""
        self._cli = None
        self._ip = None
        self._ip6 = None

    @property
    def id(self):
        return LOCAL_ID if self.local else self.host

    def run(self, cmd, timeout=240):
        if self.local:
            try:
                p = subprocess.run(["bash", "-lc", cmd], capture_output=True,
                                   text=True, timeout=timeout)
                return p.returncode, (p.stdout + p.stderr)[-6000:]
            except subprocess.TimeoutExpired:
                return 124, "timeout"
            except Exception as e:
                return 1, f"exception: {e}"
        cli = self._connect()
        if not cli:
            return 255, "ssh connect failed"
        try:
            _, o, e = cli.exec_command(cmd, timeout=timeout)
            out = o.read().decode("utf-8", "replace")
            err = e.read().decode("utf-8", "replace")
            rc = o.channel.recv_exit_status()
            return rc, (out + err)[-6000:]
        except Exception as ex:
            return 254, f"exec exception: {str(ex)[:150]}"

    def _connect(self):
        if self._cli:
            return self._cli
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.host, port=self.ssh_port, username=self.username,
                  password=self.password, timeout=25, banner_timeout=25,
                  auth_timeout=25, look_for_keys=False, allow_agent=False)
        self._cli = c
        return c

    def put(self, content: str, remote_path: str) -> bool:
        try:
            if self.local:
                os.makedirs(os.path.dirname(remote_path), exist_ok=True)
                with open(remote_path, "w") as f:
                    f.write(content)
                return True
            cli = self._connect()
            sftp = cli.open_sftp()
            try:
                with sftp.open(remote_path, "w") as f:
                    f.write(content)
            finally:
                sftp.close()
            return True
        except Exception:
            return False

    def pubip(self):
        if self._ip:
            return self._ip
        if self.local:
            # container: docker bridge IP is private -> use outbound public IP
            rc, out = self.run("curl -s --max-time 6 ifconfig.me 2>/dev/null || "
                               "curl -s --max-time 6 api.ipify.org 2>/dev/null || true", 14)
            v = (out or "").strip().splitlines()
            if v and re.match(r"^\d+\.\d+\.\d+\.\d+$", v[-1].strip()):
                self._ip = v[-1].strip()
            else:
                rc2, out2 = self.run("ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | tail -1", 15)
                lines = [x.strip() for x in (out2 or "").splitlines() if x.strip()]
                self._ip = lines[-1] if lines else self.host
        else:
            # remote: the IP we SSHed to is by definition the reachable one
            self._ip = self.host
        return self._ip

    def has_global6(self):
        rc, out = self.run("ip -6 addr show scope global 2>/dev/null | head -4", 12)
        return bool((out or "").strip())

    def close(self):
        try:
            if self._cli:
                self._cli.close()
        except Exception:
            pass
        self._cli = None


# ------------------------------------------------------------------- scan
def _classify_iface(name: str) -> str:
    n = name.lower()
    for pat, lab in (("gre", "GRE"), ("sit", "SIT"), ("ipip", "IPIP"),
                     ("tunl", "IPIP"), ("vxlan", "VXLAN"), ("wg", "WIREGUARD"),
                     ("erspan", "ERSPAN"), ("vti", "VTI"), ("xfrm", "XFRM"),
                     ("tun", "TUN")):
        if pat in n:
            return lab
    return "TUNNEL"


def _parse_scan(raw: str) -> dict:
    d = {"kernel": [], "wireguard": [], "processes": [], "services": [],
         "ports": []}
    sec = None
    wg_cur = None
    for ln in raw.splitlines():
        if ln.startswith("===K==="):
            sec = "K"; continue
        if ln.startswith("===W==="):
            sec = "W"; continue
        if ln.startswith("===P==="):
            sec = "P"; continue
        if ln.startswith("===S==="):
            sec = "S"; continue
        if ln.startswith("===L==="):
            sec = "L"; continue
        if ln.startswith("===END==="):
            break
        if not ln.strip():
            continue
        if sec == "K":
            m = re.match(r"\d+:\s+([\w.@:\-]+)\s*<?", ln)
            m2 = re.search(r"state\s+(\w+)", ln)
            if m:
                name = m.group(1).split("@")[0].rstrip(":")
                state = (m2.group(1) if m2 else "unknown").upper()
                if name in ("lo",) or name.startswith(("veth", "br-", "docker", "mtfpeer", "v_")):
                    continue
                d["kernel"].append({"iface": name, "kind": _classify_iface(name),
                                    "state": state,
                                    "ours": name.startswith("mtf-")})
        elif sec == "W":
            m = re.match(r"interface:\s+(\S+)", ln)
            if m:
                wg_cur = {"iface": m.group(1), "peers": 0}
                d["wireguard"].append(wg_cur)
            elif wg_cur is not None and re.match(r"\s*peer:\s*(\S+)", ln):
                wg_cur["peers"] += 1
            elif wg_cur is not None and "endpoint" in ln.lower():
                wg_cur["endpoint"] = ln.split("=", 1)[-1].strip() if "=" in ln else ""
        elif sec == "P":
            m = re.match(r"\s*(\d+)\s+([\d\-:]+)\s+(.*)", ln)
            if m:
                args = m.group(3).strip()
                tool = next((lab for pat, lab in TOOL_PATTERNS if pat in args.lower()), None)
                if tool:
                    d["processes"].append({"pid": m.group(1), "uptime": m.group(2),
                                           "tool": tool, "cmd": args[:200],
                                           "ours": "mtf-" in args or "/opt/mtf-inst" in args})
        elif sec == "S":
            parts = ln.split()
            if len(parts) >= 4:
                unit, load, active = parts[0], parts[1], parts[3]
                d["services"].append({"unit": unit, "load": load, "active": active,
                                      "desc": " ".join(parts[4:])[:100],
                                      "ours": unit.startswith("mtf-")})
        elif sec == "L":
            m = re.match(r"\s*(\w+)\s+\S+.*?(\S+):(\d+)\s", ln)
            if m and not ln.startswith("Netid"):
                d["ports"].append({"proto": m.group(1).upper(),
                                   "local": f"{m.group(2)}:{m.group(3)}",
                                   "line": ln.strip()[:140]})
    # dedupe
    d["ports"] = list({p["proto"] + p["local"]: p for p in d["ports"]}.values())[:40]
    return d


def scan_side(side: Side) -> dict:
    out = {"id": side.id, "name": side.name, "ok": False, "err": "", "ts": time.time()}
    rc, raw = side.run(SCAN_SCRIPT, 90)
    if rc in (0, 1) and "===END===" in raw:
        out.update(_parse_scan(raw))
        out["ok"] = True
        rc2, osr = side.run(". /etc/os-release 2>/dev/null && echo $PRETTY_NAME; uname -r", 12)
        lines = [x.strip() for x in osr.splitlines() if x.strip()]
        out["os"] = lines[0][:60] if lines else ""
        out["kernel_rel"] = lines[1][:40] if len(lines) > 1 else ""
    else:
        out["err"] = (raw or "scan failed")[:200]
    return out


def run_scan(servers: list):
    with _job_lock:
        if SCAN_JOB["running"]:
            return False
        SCAN_JOB.update(running=True, phase="start", progress="0", ts=time.time(), err="")
    try:
        sides = [Side(s) for s in (servers or [])]
        sides.insert(0, Side({"local": True, "name": "Panel container (this)"}))
        results = []
        for i, s in enumerate(sides):
            SCAN_JOB.update(phase=f"scan {s.id}", progress=f"{i + 1}/{len(sides)}")
            results.append(scan_side(s))
        book = _load(SCAN_FILE)
        for r in results:
            book[r["id"]] = r
        _save(SCAN_FILE, book)
        SCAN_JOB.update(running=False, phase="done", progress="complete")
        return True
    except Exception as ex:
        SCAN_JOB.update(running=False, phase="error", err=str(ex)[:200])
        return False


def scan_status():
    return {"running": SCAN_JOB["running"], "phase": SCAN_JOB["phase"],
            "progress": SCAN_JOB["progress"], "err": SCAN_JOB["err"],
            "results": _load(SCAN_FILE)}


# ----------------------------------------------------------------- deploy
def _log(msg):
    JOB["logs"] = (JOB["logs"] + [f"{time.strftime('%H:%M:%S')} {msg}"])[-60:]


# which port the SERVER side needs, per transport (for conflict-safe auto-assign)
UDP_SERVER = {"FRP_KCP", "FRP_QUIC", "HYSTERIA2", "TUIC", "SHADOWSOCKS",
              "GOST_KCP_FORWARD", "GOST_QUIC", "GOST_SOCKS5_KCP",
              "GOST_UDP_FORWARD", "GOST_REMOTE_UDP", "WSTUNNEL_UDP"}
KERNEL_UDP = {"wg", "ovpn", "vxlan"}


def _allocate_ports(mid: str, a, b, kernel: bool):
    """Conflict-safe port pick via portmgr (fresh scan of both ends).
    Stores P.PORT_OVERRIDES[mid]. Returns (ps, pc, pr) or default tuple."""
    from . import portmgr
    kind = P.KERNEL_MAP.get(mid) if kernel else None
    needs = {}
    if kernel:
        if kind in KERNEL_UDP:
            needs["server"] = "udp"
    else:
        needs["server"] = "udp" if mid in UDP_SERVER else "tcp"
        needs["client"] = "tcp"
    if not needs:
        return P.ports_of(mid)
    try:
        sides = [{"host": a.host, "ssh_port": a.ssh_port, "username": a.username,
                  "password": a.password}] if not a.local else []
        if b and not b.local:
            sides.append({"host": b.host, "ssh_port": b.ssh_port,
                          "username": b.username, "password": b.password})
        if sides:
            portmgr.run_scan(sides)
        rep = portmgr.last_report()
        side_ids = list((rep.get("sides") or {}).keys())
        r = portmgr.assign(mid, needs, side_ids, rep)
        if r.get("ok"):
            ports = r["ports"]
            ps, pc, pr = P.ports_of(mid)
            ps = ports.get("server", ps)
            pc = ports.get("client", pc)
            P.PORT_OVERRIDES[mid] = (ps, pc, pr)
            _log(f"{mid}: conflict-safe ports {ps}/{pc} (scanned {len(side_ids)} sides)")
        else:
            _log(f"{mid}: port auto-assign fallback to defaults ({r.get('err', '')})")
    except Exception as ex:
        _log(f"{mid}: portmgr exception: {str(ex)[:80]}")
    return P.ports_of(mid)


# ------------------------------------------------- multi-distro (not Ubuntu-only)
PM_DETECT = r"""
if command -v apt-get >/dev/null 2>&1; then echo apt
elif command -v dnf >/dev/null 2>&1; then echo dnf
elif command -v yum >/dev/null 2>&1; then echo yum
elif command -v zypper >/dev/null 2>&1; then echo zypper
elif command -v pacman >/dev/null 2>&1; then echo pacman
elif command -v apk >/dev/null 2>&1; then echo apk
else echo unknown; fi
"""

# package name per distro family: {generic: {pm: name}}
PKG_NAMES = {
    "wireguard-tools": {"apt": "wireguard-tools", "dnf": "wireguard-tools",
                        "yum": "wireguard-tools", "zypper": "wireguard-tools",
                        "pacman": "wireguard-tools", "apk": "wireguard-tools-wg"},
    "openvpn": {"apt": "openvpn", "dnf": "openvpn", "yum": "openvpn",
                "zypper": "openvpn", "pacman": "openvpn", "apk": "openvpn"},
    "openssl": {"apt": "openssl", "dnf": "openssl", "yum": "openssl",
                "zypper": "openssl", "pacman": "openssl", "apk": "openssl"},
    "iproute2": {"apt": "iproute2", "dnf": "iproute", "yum": "iproute",
                 "zypper": "iproute2", "pacman": "iproute2", "apk": "iproute2"},
    "curl": {"apt": "curl", "dnf": "curl", "yum": "curl",
             "zypper": "curl", "pacman": "curl", "apk": "curl"},
    "strongswan": {"apt": "strongswan", "dnf": "strongswan", "yum": "strongswan",
                   "zypper": "strongswan", "pacman": "strongswan", "apk": "strongswan"},
    "xl2tpd": {"apt": "xl2tpd", "dnf": "xl2tpd", "yum": "xl2tpd",
               "zypper": "xl2tpd", "pacman": "xl2tpd", "apk": "xl2tpd"},
}


def _pm_of(side: Side) -> str:
    rc, out = side.run(PM_DETECT, 20)
    pm = (out or "").strip().splitlines()
    return pm[-1].strip() if pm else "unknown"


def _pkg(side: Side, pkgs: list) -> bool:
    """Install packages with the distro's native manager (apt/dnf/yum/zypper/
    pacman/apk). Returns True when all requested tools are available after."""
    pm = _pm_of(side)
    if not pkgs:
        return True
    names = [PKG_NAMES.get(p, {}).get(pm, p) for p in pkgs]
    q = " ".join(names)
    if pm == "apt":
        cmd = ("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; "
               f"apt-get install -y -qq {q} >/dev/null 2>&1")
    elif pm in ("dnf", "yum"):
        cmd = f"{pm} install -y -q {q} >/dev/null 2>&1"
    elif pm == "zypper":
        cmd = f"zypper --non-interactive --quiet install {q} >/dev/null 2>&1"
    elif pm == "pacman":
        cmd = f"pacman -Sy --noconfirm --needed {q} >/dev/null 2>&1"
    elif pm == "apk":
        cmd = f"apk add --no-cache --quiet {q} >/dev/null 2>&1"
    else:
        _log(f"{side.id}: unknown package manager; trying raw binaries")
        return False
    rc, out = side.run(cmd, 420)
    return rc in (0, 1)  # yum/dnf exit 1 sometimes with already-installed; verify below


def _ensure_dirs(side: Side):
    side.run(f"mkdir -p {PDIR}/ssh /opt/multitunnel/bin /root/.mtf", 20)


def _push_bins(side: Side, tools: list):
    """Upload needed binaries from the panel's bin/ to the target."""
    for tool in tools:
        src = f"{BIN}/{tool}"
        if not os.path.exists(src):
            _log(f"bin missing locally: {tool}")
            continue
        rc, out = side.run(f"test -x /opt/multitunnel/bin/{tool} && echo OK || echo NO", 15)
        if "OK" in out:
            continue
        if side.local:
            side.run(f"cp {src} /opt/multitunnel/bin/ && chmod +x /opt/multitunnel/bin/{tool}", 30)
            continue
        cli = side._connect()
        sftp = cli.open_sftp()
        try:
            sftp.put(src, f"/opt/multitunnel/bin/{tool}")
        finally:
            sftp.close()
        side.run(f"chmod +x /opt/multitunnel/bin/{tool}", 15)
        _log(f"uploaded {tool} -> {side.id}")


def _mk_units(side: Side, plan: dict, mid: str, role: str):
    """Write files + enable unit (systemd) or supervisor loop (container)."""
    files = dict(plan.get("files", {}))
    unit = plan.get("unit_name") or ("mtf-" + mid.lower().replace("_", "")[:11])
    if plan.get("unit_kind") == "simple" and plan.get("exec"):
        files[f"/etc/systemd/system/{unit}.service"] = P._unit_simple(unit, plan["exec"])
    for path, content in files.items():
        if not side.put(content, path):
            _log(f"write failed {path} on {side.id}")
        side.run(f"chmod 600 {path} 2>/dev/null || true; chmod +x {path} 2>/dev/null || true", 10)
    if plan.get("unit_kind") == "oneshot":
        side.run(f"systemctl daemon-reload 2>/dev/null; "
                 f"systemctl enable {unit}.service >/dev/null 2>&1; "
                 f"systemctl restart {unit}.service 2>&1 || "
                 f"bash /usr/local/bin/{unit}.sh", 120)
    else:
        if side.local:
            # pidfile-based supervisor: kills previous child before start
            sup = (f"#!/bin/bash\n"
                   f"PIDF={PDIR}/{unit}.pid\n"
                   f"[ -f \"$PIDF\" ] && kill -9 \"$(cat $PIDF)\" 2>/dev/null\n"
                   f"while true; do\n"
                   f"  {plan['exec']} >>{BASE}/logs/{unit}.log 2>&1 &\n"
                   f"  echo $! > \"$PIDF\"\n"
                   f"  wait $!\n"
                   f"  sleep 4\n"
                   f"done\n")
            side.put(sup, f"{PDIR}/{unit}.sup.sh")
            side.run(f"chmod +x {PDIR}/{unit}.sup.sh", 10)
            # separate calls: pkill would otherwise kill its own parent shell
            # (pattern appears in the launching command's cmdline) — bracket
            # trick keeps pkill away from itself.
            side.run(f"pkill -f '[b]ash {PDIR}/{unit}.sup.sh' 2>/dev/null; "
                     f"[ -f {PDIR}/{unit}.pid ] && kill -9 $(cat {PDIR}/{unit}.pid) 2>/dev/null; true", 15)
            side.run(f"nohup bash {PDIR}/{unit}.sup.sh >/dev/null 2>&1 & echo started", 15)
        else:
            side.run(f"systemctl daemon-reload 2>/dev/null; "
                     f"systemctl enable {unit}.service >/dev/null 2>&1; "
                     f"systemctl restart {unit}.service 2>&1", 60)
    return unit


def _verify_kernel(side: Side, mid: str, role: str) -> tuple:
    kind = P.KERNEL_MAP[mid]
    a4, b4 = P.tun4(mid)
    a6, b6 = P.tun6(mid)
    ifname = ("mtf-" + mid.lower().replace("_", ""))[:15]
    rc, out = side.run(f"ip link show {ifname} 2>/dev/null | head -1", 15)
    if ifname not in out:
        return "FAIL", [f"iface {ifname} missing on {side.id}: {(out or '')[:120]}"]
    if kind in ("sit", "ip6gre", "ip6gretap", "vti6"):
        target = b6 if role == "a" else a6
        rc, out = side.run(f"ping -6 -c 3 -W 2 {target} 2>&1 | tail -2", 25)
    else:
        target = b4 if role == "a" else a4
        rc, out = side.run(f"ping -c 3 -W 2 {target} 2>&1 | tail -2", 25)
    loss = 100.0
    m = re.search(r"([\d.]+)% packet loss", out or "")
    if m:
        loss = float(m.group(1))
    if loss < 60:
        return "PASS", [f"{ifname} up, ping {target} loss {loss:.0f}%"]
    return "PARTIAL", [f"{ifname} up but ping {target} loss {loss:.0f}% "
                       f"(peer side missing / NAT / firewall)"]


def _gen_ctx(sides: list) -> dict:
    """Shared randomness/values for one method install (cert, keys, uuid...)."""
    try:
        subprocess.run(["bash", "-lc",
                        "openssl req -x509 -newkey rsa:2048 -keyout /tmp/mtftls.key "
                        "-out /tmp/mtftls.pem -days 3650 -nodes -subj '/CN=mtf.local' "
                        ">/dev/null 2>&1"], timeout=30, capture_output=True)
        crt = open("/tmp/mtftls.pem").read()
        key = open("/tmp/mtftls.key").read()
    except Exception:
        crt, key = "", ""
    return {"a_ip": sides[0].pubip(), "b_ip": sides[1].pubip(),
            "a6": "", "b6": "", "uuid": str(__import__("uuid").uuid4()),
            "pw": secrets.token_hex(12),
            "ss22": __import__("base64").b64encode(secrets.token_bytes(16)).decode(),
            "cert": {"crt": crt, "key": key},
            "real": {"priv": secrets.token_hex(32), "pub": secrets.token_hex(32)},
            "wg": {"a": {"priv": secrets.token_hex(32), "pub": secrets.token_hex(32)},
                   "b": {"priv": secrets.token_hex(32), "pub": secrets.token_hex(32)}},
            "keys": {"auth1": secrets.token_hex(32), "enc1": secrets.token_hex(16),
                     "auth2": secrets.token_hex(32), "enc2": secrets.token_hex(16),
                     "ovpn": ""}}


def _wg_keypair_local():
    """Generate a real WireGuard keypair (X25519, RFC7748 clamp) in-process."""
    import base64
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        raw = bytearray(secrets.token_bytes(32))
        raw[0] &= 248; raw[31] &= 127; raw[31] |= 64   # clamp FIRST
        k = X25519PrivateKey.from_private_bytes(bytes(raw))
        pub = k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"priv": base64.b64encode(bytes(raw)).decode(),
                "pub": base64.b64encode(pub).decode()}
    except Exception:
        raw = bytearray(secrets.token_bytes(32))
        raw[0] &= 248; raw[31] &= 127; raw[31] |= 64
        return {"priv": base64.b64encode(bytes(raw)).decode(), "pub": ""}


def _wg_keygen(side: Side, tag: str) -> dict:
    _pkg(side, ["wireguard-tools"])
    # wg genkey -> priv file; wg pubkey -> stdout; print both clearly
    rc, out = side.run("umask 077; wg genkey > /tmp/mtf-wg-priv 2>/dev/null && "
                       "echo PUB=$(wg pubkey < /tmp/mtf-wg-priv) && "
                       "echo PRIV=$(cat /tmp/mtf-wg-priv)", 40)
    pub = priv = ""
    for ln in (out or "").splitlines():
        if ln.startswith("PUB="):
            pub = ln[4:].strip()
        elif ln.startswith("PRIV="):
            priv = ln[5:].strip()
    if len(priv) > 30 and len(pub) > 30:
        return {"priv": priv, "pub": pub}
    _log(f"wg keygen on {side.id} failed (wg tool) -> local crypto fallback")
    return _wg_keypair_local()


def run_deploy(server_specs: list, mids: list, pair: bool = True):
    with _job_lock:
        if JOB["running"]:
            return False
        JOB.update(running=True, target=",".join(s.get("host") or "local" for s in server_specs),
                   current=None, done=0, total=len(mids), ok=0, partial=0, fail=0,
                   logs=[], err="", ts=time.time())
    try:
        sides = [Side(s) for s in server_specs]
        local = Side({"local": True})
        if pair and len(sides) >= 2:
            a, b = sides[0], sides[1]
            two_sided = True
        else:
            a, b = sides[0], None
            two_sided = False
        book = _load(INST_FILE)
        for mid in mids:
            JOB["current"] = mid
            is_kernel = mid in P.KERNEL_MAP
            _allocate_ports(mid, a, b, is_kernel)
            verdict, evd, meta = _deploy_one(mid, a, b, two_sided, local)
            rec = {"verdict": verdict, "evidence": evd, "ts": time.time(), **meta}
            entries = [(a.id, meta.get("role_a", "a"))]
            if two_sided and b:
                entries.append((b.id, "b"))
            for sid, srole in entries:
                hb = book.setdefault(sid, {"ts": time.time(), "methods": {}})
                mrec = dict(rec)
                mrec["role"] = srole
                hb["methods"][mid] = mrec
                hb["ts"] = time.time()
            _save(INST_FILE, book)
            JOB["done"] += 1
            JOB[{"PASS": "ok", "PARTIAL": "partial", "FAIL": "fail"}.get(verdict, "fail")] += 1
        JOB["current"] = None
        JOB["phase"] = "done"
        return True
    except Exception as ex:
        JOB["err"] = str(ex)[:300]
        _log(f"job error: {str(ex)[:200]}")
        return False
    finally:
        JOB["running"] = False
        for s in (locals().get("sides") or []):
            try:
                s.close()
            except Exception:
                pass


def _deploy_one(mid: str, a: Side, b, two_sided: bool, local: Side):
    try:
        if mid in P.KERNEL_MAP:
            return _deploy_kernel(mid, a, b, two_sided, local)
        if mid in P.PERSIST_ORDER:
            return _deploy_user(mid, a, b, two_sided, local)
        note = P.PARTIAL_NOTES.get(mid, ("پروفایل ماندگار هنوز برای این متد نیست؛ از تب Deploy تست کنید",
                                         "no persistent profile yet; use the Deploy tab"))
        return "PARTIAL", [f"profile-only: {note[1]}"], {"kind": "profile", "role_a": "single"}
    except Exception as ex:
        return "FAIL", [f"exception: {str(ex)[:200]}"], {"kind": "error", "role_a": "?"}


def _prep_kernel(side: Side, mid: str):
    kind = P.KERNEL_MAP[mid]
    pkgs = []
    if kind == "wg":
        pkgs.append("wireguard-tools")
    if kind == "ovpn":
        pkgs.append("openvpn")
    pkgs.append("iproute2")
    _pkg(side, pkgs)
    if kind == "ovpn":
        rc, out = side.run("command -v openvpn && echo OVPN-OK || echo OVPN-NO", 20)
        if "OVPN-OK" not in out:
            return False
    return True


def _firewall_allow(side: Side, port: int, kind: str):
    """Open a port/proto via whatever firewall exists: ufw / firewalld /
    nftables / plain iptables — multi-distro safe."""
    noprot = {"gre", "gretap", "ipip", "sit", "vti", "vti6", "ip6gre", "ip6gretap"}
    proto = {"wg": "udp", "ovpn": "udp", "vxlan": "udp"}.get(kind, kind)
    if kind in noprot:
        fw_port = f"-p {proto}"
        fw_cmd_ufw = f"ufw allow {proto}"
        fw_cmd_fwalld = f"firewall-cmd --permanent --add-rich-rule='rule protocol value=\"{proto}\" accept'"
        ipt = f"iptables -C INPUT -p {proto} -j ACCEPT 2>/dev/null || iptables -I INPUT -p {proto} -j ACCEPT"
    else:
        fw_port = f"{port}/{proto}"
        fw_cmd_ufw = f"ufw allow {port}/{proto}"
        fw_cmd_fwalld = f"firewall-cmd --permanent --add-port={port}/{proto}"
        ipt = (f"iptables -C INPUT -p {proto} --dport {port} -j ACCEPT 2>/dev/null || "
               f"iptables -I INPUT -p {proto} --dport {port} -j ACCEPT")
    side.run(
        f"if command -v ufw >/dev/null 2>&1; then {fw_cmd_ufw} >/dev/null 2>&1 || true; "
        f"elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then "
        f"{fw_cmd_fwalld} >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; "
        f"else {ipt} 2>/dev/null; fi; true", 45)


def _deploy_kernel(mid: str, a: Side, b, two_sided: bool, local: Side) -> tuple:
    kind = P.KERNEL_MAP[mid]
    evd = []
    if not two_sided:
        # single side on chosen target (a). Kernel tunnels need a peer IP.
        peer_ip = b.pubip() if b else None
        return "PARTIAL", ["single-target kernel tunnel: local side only, "
                           f"peer side not configured (select pair mode with a 2nd server)"], {
            "kind": "kernel", "role_a": "single", "iface": ("mtf-" + mid.lower().replace("_", ""))[:15]}
    ctx = _gen_ctx([a, b])
    if not two_sided:
        pass  # handled above
    if kind in ("ip6gre", "ip6gretap", "vti6"):
        if not (a.has_global6() and b.has_global6()):
            return "FAIL", ["both ends need global IPv6 for " + mid], {"kind": "kernel", "role_a": "a"}
        for s, key in ((a, "a6"), (b, "b6")):
            rc, out = s.run("ip -6 addr show scope global | grep -oE '[0-9a-f:]+/[0-9]+' | head -1", 12)
            ctx[key] = ((out or "").strip().splitlines() or [""])[-1].split("/")[0].strip()
        if not ctx["a6"] or not ctx["b6"]:
            return "FAIL", ["no global IPv6 address found"], {"kind": "kernel", "role_a": "a"}
    if kind == "ovpn":
        rc, out = a.run("openvpn --genkey secret /tmp/mtf-ovpn.key 2>/dev/null || "
                        "(apt-get install -y -qq openvpn >/dev/null 2>&1 && "
                        "openvpn --genkey secret /tmp/mtf-ovpn.key); cat /tmp/mtf-ovpn.key", 300)
        ctx["keys"]["ovpn"] = "\n".join((out or "").splitlines()[1:]).strip()
        if "-----BEGIN" not in ctx["keys"]["ovpn"] and len(ctx["keys"]["ovpn"]) < 60:
            return "FAIL", ["cannot generate openvpn static key"], {"kind": "kernel", "role_a": "a"}
    if kind == "wg":
        ka = _wg_keygen(a, "a")
        kb = _wg_keygen(b, "b")
        if not kb.get("pub"):
            return "FAIL", ["wireguard keygen failed on server side"], {"kind": "kernel", "role_a": "a"}
        ctx["wg"] = {"a": ka, "b": kb}
    plans = P.kernel_plan(mid, ctx)
    evd2 = []
    # 1) create BOTH sides first (B=server, A=client)
    for side, role in ((b, "b"), (a, "a")):
        if not _prep_kernel(side, mid):
            evd2.append(f"{mid}: deps missing on {side.id}")
            continue
        ps, pc, pr = P.ports_of(mid)
        if role == "b":
            _firewall_allow(side, ps, kind)
        _mk_units(side, plans[role], mid, role)
    # 2) then verify (A initiates, so B learns the NAT'd endpoint / path warms up)
    time.sleep(4)
    verdicts = []
    for side, role in ((a, "a"), (b, "b")):
        v, e = _verify_kernel(side, mid, role)
        verdicts.append(v)
        evd2.extend([f"{side.id}: {x}" for x in e])
    if not verdicts:
        verdicts, evd2 = ["FAIL"], ["no side could be created"]
    evd.extend(evd2)
    final = "PASS" if all(v == "PASS" for v in verdicts) else (
        "PARTIAL" if "PARTIAL" in verdicts else "FAIL")
    ifname = ("mtf-" + mid.lower().replace("_", ""))[:15]
    return final, evd[:8], {"kind": "kernel", "role_a": "a", "iface": ifname,
                            "unit": ifname, "peer": b.id}


def _deploy_user(mid: str, a: Side, b, two_sided: bool, local: Side) -> tuple:
    ctx = _gen_ctx([a, b or a])
    ctx["b_ssh_port"] = b.ssh_port if b else 22
    plan = P.user_plan(mid, ctx)
    evd = []
    _push_bins(a, plan["bins"])
    # origin service where needed
    if plan.get("origin") == "B" and b:
        _push_bins(b, [])
        for path, content in P._origin_unit(P.PDIR).items():
            b.put(content, path); b.run(f"chmod 755 {PDIR}/origin 2>/dev/null; true", 10)
        b.run("systemctl daemon-reload 2>/dev/null; systemctl enable --now mtf-origin.service 2>&1 || "
              f"nohup python3 -m http.server 5201 --bind 0.0.0.0 --directory {PDIR}/origin >>{BASE}/logs/origin.log 2>&1 &", 30)
        evd.append("origin http.server up on B:5201")
    elif plan.get("origin") == "A":
        for path, content in P._origin_unit(P.PDIR).items():
            a.put(content, path); a.run(f"chmod 755 {PDIR}/origin 2>/dev/null; true", 10)
        a.run("systemctl daemon-reload 2>/dev/null; systemctl enable --now mtf-origin.service 2>&1 || "
              f"nohup python3 -m http.server 5201 --bind 0.0.0.0 --directory {PDIR}/origin >>{BASE}/logs/origin.log 2>&1 &", 30)
        evd.append("origin http.server up on A:5201")

    if mid.startswith("SSH_"):
        # key-based auth: generate key on A, append pubkey to B authorized_keys
        if not two_sided or b is None:
            return "PARTIAL", ["SSH forwards need pair mode (2 servers) for key install"], {
                "kind": "userspace", "role_a": "single"}
        a.run(f"rm -f {PDIR}/ssh/mtf_key*; ssh-keygen -t ed25519 -N '' -f {PDIR}/ssh/mtf_key -q", 30)
        rc, pub = a.run(f"cat {PDIR}/ssh/mtf_key.pub", 15)
        pubk = (pub or "").strip().splitlines()
        if not pubk or "ssh-" not in pubk[0]:
            return "FAIL", ["ssh-keygen failed on A"], {"kind": "userspace", "role_a": "a"}
        b.run(f"mkdir -p /root/.ssh && chmod 700 /root/.ssh; grep -qF '{pubk[0]}' /root/.ssh/authorized_keys 2>/dev/null || "
              f"echo '{pubk[0]}' >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys", 20)
        evd.append("ssh key installed A->B")

    # reality keys from B's xray binary
    if mid.startswith("VLESS_") and "REALITY" in mid:
        rc, out = a.run(f"{BIN}/xray x25519 2>/dev/null | head -2", 30)
        priv = [l.split(":")[1].strip() for l in (out or "").splitlines() if "Private" in l]
        pub = [l.split(":")[1].strip() for l in (out or "").splitlines() if "Public" in l]
        if priv and pub:
            ctx["real"] = {"priv": priv[0], "pub": pub[0]}
            plan = P.user_plan(mid, ctx)  # regenerate with real keys
        else:
            evd.append("x25519 gen failed; reality may not verify")

    ps, pc, pr = P.ports_of(mid)
    verdicts = []
    units = {}
    # free the allocated ports from any stale previous install (best effort)
    for side in ([b] if (two_sided and b) else []) + [a]:
        side.run("; ".join([f"fuser -k -n tcp {p} 2>/dev/null; fuser -k -n udp {p} 2>/dev/null; "
                            f"pkill -f '0.0.0.0:{p} ' 2>/dev/null" for p in (ps, pc, pr)]) + "; true", 30)
    # B side (server) first
    if two_sided and b:
        units["b"] = _mk_units(b, plan["B"], mid, "b")
        _firewall_allow(b, ps, "user")
        if mid in ("FRP_KCP", "FRP_QUIC", "HYSTERIA2", "TUIC"):
            _firewall_allow(b, ps, "wg")  # udp
        evd.append(f"server unit on {b.id}: {units['b']}")
    # A side (client)
    units["a"] = _mk_units(a, plan["A"], mid, "a")
    evd.append(f"client unit on {a.id}: {units['a']}")
    time.sleep(4)
    # verify
    ok_any = False
    for side_name, cmd, expect in plan["verify"]:
        side = a if side_name == "A" else (b or a)
        rc, out = side.run(cmd, 30)
        code = (out or "").strip().splitlines()
        code = code[-1].strip() if code else ""
        good = any(code.startswith(e) or code == e for e in expect.split("|"))
        evd.append(f"verify on {side.id}: {cmd[:70]} -> {code or 'no-reply'} (expect {expect})")
        if good:
            ok_any = True
    if not plan["verify"]:
        rc, out = a.run(f"systemctl is-active {units['a']}.service 2>/dev/null || pgrep -f '{PDIR}' | head -1", 15)
        ok_any = ("active" in (out or "")) or bool((out or "").strip())
        evd.append(f"unit/process check on {a.id}: {(out or '').strip()[:60]}")
    if two_sided and b:
        final = "PASS" if ok_any else "PARTIAL"
    else:
        final = "PARTIAL" if ok_any else "PARTIAL"
        evd.append("single-target mode: server side absent, client cannot verify end-to-end")
    return final, evd[:8], {"kind": "userspace", "role_a": "a",
                            "unit": units["a"], "port": pc, "server_port": ps,
                            "peer": b.id if b else None}


# ------------------------------------------------------------------ remove
def run_remove(server_spec: dict, mid: str) -> dict:
    side = Side(server_spec)
    out = {"ok": False, "removed": [], "err": ""}
    try:
        ifname = ("mtf-" + mid.lower().replace("_", ""))[:15]
        rc, o = side.run(
            f"systemctl disable --now {ifname}.service 2>/dev/null; "
            f"systemctl disable --now mtf-{mid.lower()[:11]}.service 2>/dev/null; "
            f"pkill -f '{PDIR}/{mid.lower()[:11]}' 2>/dev/null; "
            f"pkill -f 'mtf-{ifname}' 2>/dev/null; "
            f"ip link del {ifname} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{ifname}.service /etc/systemd/system/mtf-{mid.lower()[:11]}.service "
            f"/usr/local/bin/{ifname}.sh /etc/wireguard/{ifname}.data "
            f"/etc/openvpn/mtf-{ifname}.conf /etc/openvpn/mtf-{ifname}.key; "
            f"rm -rf {PDIR}/{mid.lower()[:11]}* {PDIR}/mtf-{ifname}*; "
            f"systemctl daemon-reload 2>/dev/null; echo RM-DONE", 90)
        if "RM-DONE" in o:
            out["ok"] = True
            out["removed"] = [ifname]
        else:
            out["err"] = (o or "remove failed")[:200]
        book = _load(INST_FILE)
        if side.id in book and mid in book[side.id].get("methods", {}):
            del book[side.id]["methods"][mid]
            _save(INST_FILE, book)
    except Exception as ex:
        out["err"] = str(ex)[:200]
    finally:
        side.close()
    return out


def restart_supervisors():
    """Start persistent userspace supervisors (container has no systemd).
    Called at panel startup so tunnels survive container restarts."""
    import glob
    started = 0
    for sup in sorted(glob.glob(f"{PDIR}/*.sup.sh")):
        try:
            p = subprocess.run(["bash", "-lc",
                                f"pgrep -f 'bash {sup}$' >/dev/null && echo RUN || echo NO"],
                               capture_output=True, text=True, timeout=10)
            if "RUN" in (p.stdout or ""):
                continue
        except Exception:
            pass
        subprocess.Popen(["bash", "-lc", f"nohup bash {sup} >/dev/null 2>&1 &"],
                         start_new_session=True)
        started += 1
    if started:
        state.event("info", "server-tunnels", f"restarted {started} tunnel supervisor(s)")
    return started


def install_status():
    return {"job": JOB, "book": _load(INST_FILE),
            "persist": list(P.PERSIST_ORDER),
            "profile_only": sorted(P.PARTIAL_NOTES.keys())}
