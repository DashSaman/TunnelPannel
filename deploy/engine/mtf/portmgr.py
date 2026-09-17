#!/usr/bin/env python3
"""MTF port manager — conflict-safe port allocation for public servers.

Every tunnel needs ports; public servers already run other services. This
module:
  1. scans listening ports on every known side (panel-local + SSH servers)
  2. builds a global "occupied" set (tcp+udp), plus protocol-level reservations
     (gre/ipip/sit eat protocol space, not ports)
  3. auto-assigns free ports inside configured ranges, per method, per family
  4. stores allocations in data/port_alloc.json and re-verifies before install

IPv6 note: Linux binds are dual-stack by default for TCP (`0.0.0.0` vs `::`);
we check both v4 and v6 listener tables, and UDP the same way, so one
allocation is safe for both families.
"""
import ipaddress
import json
import os
import re
import socket
import threading
import time

from . import state
from .servertunnels import Side, SCAN_FILE

BASE = "/opt/multitunnel"
DATA = f"{BASE}/data"
ALLOC_FILE = f"{DATA}/port_alloc.json"

# port ranges we are allowed to hand out, per transport family
RANGES = {
    "tcp": (21000, 25999),
    "udp": (26000, 29999),
}
# protocol-space (no port): ip-proto must be free on BOTH ends
IP_PROTO_RESERVE = {47: "gre", 6: "gre-in-tcp", 4: "ipip", 41: "sit", 115: "l2tp",
                    50: "esp", 51: "ah", 137: "mpls"}
# well-known ports that must never be allocated even if free right now
NEVER = {22, 53, 80, 443, 67, 68, 123, 179, 389, 445, 465, 500, 514, 587, 623,
         636, 873, 1080, 1194, 1433, 1723, 1812, 1813, 2222, 2223, 3000, 3128,
         3306, 3389, 4500, 5060, 5061, 51820, 5432, 5555, 6379, 8000, 8080,
         8081, 8443, 8888, 9000, 9001, 9090, 9200, 9443, 27017, 5201}
# panel-local always-reserved
LOCAL_RESERVE = {9443, 5201}

JOB = {"running": False, "phase": "", "err": "", "ts": None}
_lock = threading.Lock()


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# ------------------------------------------------------------- listening scan
def _parse_ss(raw: str) -> list:
    """Parse `ss -tulnp` output into [{proto, addr, port, proc}]."""
    out = []
    for ln in raw.splitlines():
        ln = ln.rstrip()
        if not ln or ln.lower().startswith("netid"):
            continue
        parts = ln.split()
        if len(parts) < 5:
            continue
        proto = parts[0].upper().replace("TCP", "TCP").replace("UDP", "UDP")
        if proto not in ("TCP", "UDP"):
            continue
        addr = parts[4]
        m = re.match(r"^(.*):(\d+|\*)$", addr)
        if not m:
            continue
        host, port = m.group(1), m.group(2)
        proc = ""
        pm = re.search(r'\(\("([^"]+)"', ln)
        if pm:
            proc = pm.group(1)[:40]
        try:
            port_i = int(port)
        except Exception:
            # `*:*` for mcast etc — skip
            continue
        out.append({"proto": proto, "addr": host, "port": port_i, "proc": proc})
    return out


def _scan_local() -> dict:
    out = {"listeners": [], "ip_proto": [], "err": ""}
    try:
        import subprocess
        p = subprocess.run(["ss", "-tulnpH"], capture_output=True, text=True, timeout=20)
        out["listeners"] = _parse_ss(p.stdout or "")
        # ip protocol space: read /proc/net/snmp for rough conflict awareness
        out["ip_proto"] = _ip_proto_in_use_local()
    except Exception as e:
        out["err"] = str(e)[:150]
    return out


def _ip_proto_in_use_local() -> list:
    """Kernel IP protocols carrying traffic we could collide with (best effort)."""
    protos = set()
    try:
        # xfrm policies (vti/ipsec), l2tp, sit/ipip registered via /proc
        import subprocess
        for cmd, tag in ((["ip", "xfrm", "policy", "list"], 50),):
            pass
        p = subprocess.run(["ip", "xfrm", "policy", "list"], capture_output=True,
                           text=True, timeout=10)
        if p.returncode == 0 and (p.stdout or "").strip():
            protos.add("xfrm/ipsec")
        if os.path.exists("/proc/net/ip_gre") and open("/proc/net/ip_gre").read().strip():
            pass  # files list tunnels, presence of text means configured gre
        for f, tag in (("/proc/net/ipip", "ipip"), ("/proc/net/ip6_tunnel", "sit/ip6"),
                       ("/proc/net/ip_gre", "gre"), ("/proc/net/ip6gre", "ip6gre")):
            try:
                body = open(f).read().strip().splitlines()
                if len(body) > 1:  # header only = none
                    protos.add(tag)
            except Exception:
                pass
    except Exception:
        pass
    return sorted(protos)


def _scan_remote(spec: dict) -> dict:
    s = Side(spec)
    out = {"listeners": [], "ip_proto": [], "err": ""}
    try:
        rc, raw = s.run("ss -tulnpH 2>/dev/null || netstat -tulnpH 2>/dev/null", 40)
        out["listeners"] = _parse_ss(raw or "")
        rc2, raw2 = s.run("ip xfrm policy list 2>/dev/null | head -5; "
                          "ls /proc/net/ip_gre /proc/net/ipip /proc/net/ip6_tunnel "
                          "/proc/net/ip6gre 2>/dev/null", 15)
        if "xfrm" in (raw2 or ""):
            out["ip_proto"].append("xfrm/ipsec")
        for f, tag in (("ip_gre", "gre"), ("ipip", "ipip"),
                       ("ip6_tunnel", "sit/ip6"), ("ip6gre", "ip6gre")):
            if re.search(rf"/proc/net/{f}\b", raw2 or ""):
                out["ip_proto"].append(tag)
    except Exception as e:
        out["err"] = str(e)[:150]
    finally:
        s.close()
    return out


def run_scan(servers: list) -> dict:
    """Scan panel + given SSH servers; returns {side_id: report}."""
    with _lock:
        if JOB["running"]:
            return {"ok": False, "err": "scan already running"}
        JOB.update(running=True, phase="scanning", err="", ts=time.time())
    try:
        book = _load(os.path.join(DATA, "port_scan.json"), {})
        rep = {"ts": time.time(), "sides": {}}
        rep["sides"]["panel-local"] = _scan_local()
        for spec in (servers or [])[:12]:
            if not (spec.get("host") or "").strip():
                continue
            sid = spec["host"]
            JOB["phase"] = f"scan {sid}"
            rep["sides"][sid] = _scan_remote(spec)
        _save(os.path.join(DATA, "port_scan.json"), rep)
        JOB["running"] = False
        JOB["phase"] = "done"
        return {"ok": True, "report": rep}
    except Exception as e:
        JOB.update(running=False, phase="error", err=str(e)[:200])
        return {"ok": False, "err": str(e)[:200]}


def last_report() -> dict:
    rep = _load(os.path.join(DATA, "port_scan.json"), {})
    if not rep:
        rep = {"ts": time.time(), "sides": {"panel-local": _scan_local()}}
        _save(os.path.join(DATA, "port_scan.json"), rep)
    return rep


# ---------------------------------------------------------------- allocations
def occupied_set(report: dict) -> dict:
    """{side_id: {('TCP', port), ...}} + never-list."""
    occ = {}
    for sid, r in (report.get("sides") or {}).items():
        s = set()
        for l in r.get("listeners", []):
            s.add((l["proto"], l["port"]))
        for p in LOCAL_RESERVE if sid == "panel-local" else ():
            s.add(("TCP", p)); s.add(("UDP", p))
        occ[sid] = s
    return occ


def conflicts_for(mid: str, ports: dict, report: dict) -> list:
    """Given {role: (proto, port)} test against occupied set; returns list."""
    occ = occupied_set(report)
    bad = []
    for role, (proto, port) in (ports or {}).items():
        for sid, s in occ.items():
            if (proto, port) in s:
                bad.append({"mid": mid, "role": role, "proto": proto,
                            "port": port, "side": sid})
    return bad


def free_port(report: dict, proto: str, side_ids: list, start: int = None) -> int:
    """Find a port free on ALL given sides (and in NEVER/RANGE rules)."""
    proto = (proto or "tcp").upper()
    occ = occupied_set(report)
    lo, hi = RANGES.get(proto.lower(), (21000, 29999))
    cand = start if (start and lo <= start <= hi) else lo
    # also avoid anything allocated before
    allocs = _load(ALLOC_FILE, {})
    taken = set()
    for a in allocs.values():
        for v in (a.get("ports") or {}).values():
            if v:
                taken.add(v)
    for port in range(cand, hi + 1):
        if port in NEVER or port in taken:
            continue
        if all((proto, port) not in occ.get(sid, set()) for sid in side_ids):
            return port
    return 0


def assign(mid: str, needs: dict, side_ids: list, report: dict = None) -> dict:
    """needs = {role: proto} -> allocate {role: port} free on all sides.
    Stores + returns allocation record."""
    report = report or last_report()
    allocs = _load(ALLOC_FILE, {})
    prev = allocs.get(mid, {})
    ports = {}
    for role, proto in needs.items():
        old = (prev.get("ports") or {}).get(role)
        p = free_port(report, proto, side_ids, start=old)
        if not p:
            return {"ok": False, "err": f"no free {proto} port in range for {role}"}
        ports[role] = p
    rec = {"mid": mid, "ports": ports, "sides": side_ids, "ts": time.time()}
    allocs[mid] = rec
    _save(ALLOC_FILE, allocs)
    state.event("info", "ports", f"auto-assigned {mid}: {ports} on {side_ids}")
    return {"ok": True, **rec}


def allocations() -> dict:
    return {"allocs": _load(ALLOC_FILE, {}),
            "ranges": RANGES, "never": sorted(NEVER)}


def release(mid: str) -> dict:
    allocs = _load(ALLOC_FILE, {})
    if mid in allocs:
        del allocs[mid]
        _save(ALLOC_FILE, allocs)
    return {"ok": True}


def report_conflicts(report: dict = None) -> dict:
    """Human-readable conflict summary for the Ports tab."""
    report = report or last_report()
    occ = occupied_set(report)
    rows = []
    for sid, s in occ.items():
        for (proto, port) in sorted(s, key=lambda x: x[1]):
            rows.append({"side": sid, "proto": proto, "port": port})
    return {"sides": {k: len(v) for k, v in occ.items()}, "rows": rows[:200],
            "ts": report.get("ts")}


def ip_proto_report() -> dict:
    """Which ip-protocols are consumed on which side (gre/ipip/sit/esp...)."""
    rep = last_report()
    return {"ts": rep.get("ts"),
            "sides": {sid: r.get("ip_proto", [])
                      for sid, r in (rep.get("sides") or {}).items()}}
