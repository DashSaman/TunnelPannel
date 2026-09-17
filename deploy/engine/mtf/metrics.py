#!/usr/bin/env python3
"""MTF metrics — lightweight host sampling for the monitoring dashboard.

The panel container runs privileged, so /proc is the host's. We sample:
  * cpu% (delta across /proc/stat)
  * ram used/total (MemAvailable)
  * loadavg
  * net rx/tx bytes rate (first global iface aggregate)
  * tcp established count, conntrack count if available
A 240-point ring (~20 min @ 5 s) is kept in memory and mirrored to
data/metrics_history.json so charts survive restarts.
"""
import json
import os
import re
import threading
import time

BASE = "/opt/multitunnel"
DATA = f"{BASE}/data"
HIST_FILE = f"{DATA}/metrics_history.json"
MAXPTS = 240

_lock = threading.Lock()
_hist = {"ts": [], "cpu": [], "ram": [], "rx": [], "tx": [], "estab": []}
_last = {"stat": None, "net": None, "t": 0.0}
_thr = None


def _read_stat():
    cpu = None
    with open("/proc/stat") as f:
        for ln in f:
            if ln.startswith("cpu "):
                parts = [int(x) for x in ln.split()[1:9]]
                idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
                cpu = (sum(parts), idle)
                break
    return cpu


def _read_ram():
    info = {}
    with open("/proc/meminfo") as f:
        for ln in f:
            k = ln.split(":")
            if len(k) == 2:
                info[k[0]] = int(re.sub(r"\D", "", k[1]) or 0)
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    return total, avail


def _read_net():
    rx = tx = 0
    try:
        with open("/proc/net/dev") as f:
            for ln in f.readlines()[2:]:
                parts = ln.split()
                name = parts[0].rstrip(":")
                if name in ("lo",) or name.startswith(("veth", "docker", "br-")):
                    continue
                rx += int(parts[1]); tx += int(parts[9])
    except Exception:
        pass
    return rx, tx


def _read_estab():
    n = 0
    try:
        with open("/proc/net/tcp") as f:
            for ln in f.readlines()[1:]:
                if ln.split()[3] == "01":
                    n += 1
        with open("/proc/net/tcp6") as f:
            for ln in f.readlines()[1:]:
                if ln.split()[3] == "01":
                    n += 1
    except Exception:
        pass
    return n


def sample() -> dict:
    now = time.time()
    stat = _read_stat()
    rx, tx = _read_net()
    total, avail = _read_ram()
    cpu_pct = None
    dt = now - _last["t"]
    if _last["stat"] and stat and dt >= 0.5:
        d_all = stat[0] - _last["stat"][0]
        d_idle = stat[1] - _last["stat"][1]
        if d_all > 0:
            cpu_pct = round(100.0 * (1.0 - d_idle / d_all), 1)
    drx = dtx = None
    if _last["net"] and dt >= 0.5:
        drx = max(0, rx - _last["net"][0]) / dt
        dtx = max(0, tx - _last["net"][1]) / dt
    _last.update(stat=stat, net=(rx, tx), t=now)
    try:
        load1 = float(open("/proc/loadavg").read().split()[0])
    except Exception:
        load1 = None
    snap = {"ts": now, "cpu": cpu_pct,
            "ram_pct": round(100.0 * (total - avail) / total, 1) if total else None,
            "ram_mb": round((total - avail) / 1024, 0) if total else None,
            "ram_total_mb": round(total / 1024, 0) if total else None,
            "load1": load1,
            "rx_bps": round(drx) if drx is not None else None,
            "tx_bps": round(dtx) if dtx is not None else None,
            "estab": _read_estab()}
    with _lock:
        if cpu_pct is not None or not _hist["ts"]:
            _hist["ts"].append(snap["ts"])
            _hist["cpu"].append(cpu_pct)
            _hist["ram"].append(snap["ram_pct"])
            _hist["rx"].append(snap["rx_bps"])
            _hist["tx"].append(snap["tx_bps"])
            _hist["estab"].append(snap["estab"])
            for k in _hist:
                del _hist[k][:-MAXPTS]
    return snap


def _loop():
    while True:
        try:
            sample()
            if int(time.time()) % 60 == 0:
                _persist()
        except Exception:
            pass
        time.sleep(5)


def _persist():
    try:
        with _lock:
            data = dict(_hist)
        tmp = HIST_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, HIST_FILE)
    except Exception:
        pass


def start_bg():
    global _thr
    try:
        if os.path.exists(HIST_FILE):
            with open(HIST_FILE) as f:
                d = json.load(f)
            with _lock:
                _hist.update({k: d.get(k, [])[-MAXPTS:] for k in _hist})
    except Exception:
        pass
    if _thr and _thr.is_alive():
        return
    _thr = threading.Thread(target=_loop, daemon=True)
    _thr.start()


def history(limit: int = 120) -> dict:
    with _lock:
        h = {k: v[-limit:] for k, v in _hist.items()}
    return h


def info() -> dict:
    """Static-ish system info for the dashboard header."""
    out = {"kernel": "", "uptime_s": 0, "cpus": 0}
    try:
        out["kernel"] = open("/proc/sys/kernel/osrelease").read().strip()[:40]
    except Exception:
        pass
    try:
        out["uptime_s"] = int(float(open("/proc/uptime").read().split()[0]))
    except Exception:
        pass
    try:
        out["cpus"] = os.cpu_count() or 0
    except Exception:
        pass
    return out
