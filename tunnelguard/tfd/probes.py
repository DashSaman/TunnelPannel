"""TunnelGuard — probe engine: ICMP via system `ping`, TCP fallback, scoring.

Design notes (honest engineering):
- We shell out to the system `ping` binary per cycle (no raw sockets needed,
  works well as root, kernel-provided timestamps). Jitter is approximated by
  ping's mdev statistic — good enough for ranking tunnels, not lab-grade.
- A cycle = N packets; a cycle is "bad" when loss% >= loss_threshold or
  avg rtt >= latency_spike or zero replies.
- TCP fallback: when ICMP is administratively degraded we TCP-connect to
  tcp_fallback_port through the tunnel source address.
- Scoring: weighted 0..100 (loss/latency/jitter/stability). Weights are
  tunable from the dashboard.
"""
from __future__ import annotations

import math
import re
import shutil
import socket
import subprocess
import threading
import time

from . import config

_PING_STATS = re.compile(
    r"=\s*(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)\s*ms"
)
_PING_LOSS = re.compile(r"(?P<loss>[\d.]+)%\s*packet\s*loss", re.I)
_PING_BAD = ("Network is unreachable", "unreachable", "Operation not permitted",
             "Host Unreachable", "100% packet loss")


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ------------------------------------------------------------------ ICMP
def ping_cycle(target: str, count: int, timeout_s: float,
               source: str | None = None, iface: str | None = None) -> dict:
    """One probe cycle. Returns dict(rtt_ms, loss_pct, jitter_ms, ok, detail)."""
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "ok": False, "detail": "ping binary not found"}
    cmd = [ping_bin, "-c", str(count), "-W", str(max(1, int(timeout_s))),
           "-i", "0.3", "-q", target]
    if source:
        cmd += ["-I", source]
    elif iface:
        cmd += ["-I", iface]
    try:
        cp = _run(cmd, timeout=timeout_s * count + 6)
    except subprocess.TimeoutExpired:
        return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "ok": False, "detail": "probe timeout"}
    out = cp.stdout + cp.stderr
    loss = 100.0
    m = _PING_LOSS.search(out)
    if m:
        loss = float(m.group("loss"))
    stats = _PING_STATS.search(out)
    rtt = float(stats.group("avg")) if stats else None
    jitter = float(stats.group("mdev")) if stats else None
    ok = loss < 100.0 and rtt is not None and rtt < config.DEFAULT_SETTINGS["latency_spike_ms"]
    if not ok:
        for bad in _PING_BAD:
            if bad.lower() in out.lower():
                return {"rtt_ms": rtt, "loss_pct": loss, "jitter_ms": jitter,
                        "ok": False, "detail": bad}
    return {"rtt_ms": rtt, "loss_pct": loss, "jitter_ms": jitter, "ok": ok,
            "detail": None if ok else out.strip().splitlines()[-1][:120] if out.strip() else "no reply"}


# ------------------------------------------------------------------ TCP
def tcp_cycle(target: str, port: int, source: str | None = None,
              timeout_s: float = 2.0) -> dict:
    """TCP connect probe — measures connect time as latency proxy."""
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        if source:
            try:
                s.bind((source, 0))
            except OSError as e:
                return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                        "ok": False, "detail": f"bind {source}: {e}"}
        s.connect((target, port))
        rtt = (time.monotonic() - t0) * 1000.0
        return {"rtt_ms": rtt, "loss_pct": 0.0, "jitter_ms": None, "ok": True,
                "detail": None}
    except OSError as e:
        return {"rtt_ms": None, "loss_pct": 100.0, "jitter_ms": None,
                "ok": False, "detail": str(e)[:120]}
    finally:
        try:
            s.close()
        except OSError:
            pass


# ------------------------------------------------------------------ SOCKS5
# Through-tunnel probe for userspace proxy tunnels (Hedioum Pool Tunnel, and
# any engine that exposes a local SOCKS5 ingress instead of an L3 interface).
# The CONNECT handshake itself is the health signal: if the hub->foreign pipe
# is dead, the proxy cannot complete the reply — exactly the failure we want
# the FSM to see. RTT = full SOCKS5 connect time through the tunnel.
_SOCKS_GREETING = b"\x05\x01\x00"          # VER=5, 1 method, no-auth
_SOCKS_CHOICE_OK = b"\x05\x00"


def _socks5_connect(proxy_host: str, proxy_port: int, target_host: str,
                    target_port: int, timeout_s: float) -> socket.socket:
    """Raw SOCKS5 CONNECT (no deps). Raises OSError on any refusal."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout_s)
    s.settimeout(timeout_s)
    try:
        s.sendall(_SOCKS_GREETING)
        resp = s.recv(2)
        if len(resp) < 2 or resp[0:1] != b"\x05":
            raise OSError("not a SOCKS5 proxy")
        if resp[1:2] != b"\x00":
            raise OSError(f"proxy refused auth method {resp[1:2].hex()}")
        # CONNECT request: prefer ATYP=1 for literals, ATYP=3 for hostnames
        try:
            socket.inet_aton(target_host)
            atyp, addr = b"\x01", socket.inet_aton(target_host)
        except OSError:
            atyp = b"\x03"
            host_b = target_host.encode("idna") if any(
                ord(ch) > 127 for ch in target_host) else target_host.encode()
            addr = bytes([len(host_b)]) + host_b
        port_b = int(target_port).to_bytes(2, "big")
        s.sendall(b"\x05\x01\x00" + atyp + addr + port_b)
        rep = s.recv(4)
        if len(rep) < 4 or rep[1] != 0:
            code = rep[1] if len(rep) >= 2 else -1
            raise OSError(f"SOCKS CONNECT failed (reply {code})")
        # drain BND.ADDR/BND.PORT depending on ATYP
        atyp_r = rep[3:4]
        need = {b"\x01": 4, b"\x03": 1, b"\x04": 16}.get(atyp_r, 4)
        extra = s.recv(need + 2)
        if atyp_r == b"\x03" and len(extra) >= 1:
            dlen = extra[0]
            while len(extra) < 1 + dlen + 2:
                chunk = s.recv(1 + dlen + 2 - len(extra))
                if not chunk:
                    break
                extra += chunk
        return s
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise


def socks5_cycle(socks_port: int, target_host: str, target_port: int = 443,
                 proxy_host: str = "127.0.0.1", count: int = 3,
                 timeout_s: float = 4.0) -> dict:
    """One probe cycle through a local SOCKS5 tunnel ingress.
    Returns the same shape as ping_cycle/tcp_cycle so the FSM scoring
    treats proxy tunnels identically to kernel tunnels."""
    rtts: list[float] = []
    fails = 0
    detail = None
    for _ in range(max(1, count)):
        t0 = time.monotonic()
        try:
            s = _socks5_connect(proxy_host, socks_port, target_host,
                                target_port, timeout_s)
            rtts.append((time.monotonic() - t0) * 1000.0)
            try:
                s.close()
            except OSError:
                pass
        except (OSError, ValueError) as e:
            fails += 1
            detail = str(e)[:120]
    loss = 100.0 * fails / max(1, count)
    rtt = round(sum(rtts) / len(rtts), 2) if rtts else None
    jitter = None
    if len(rtts) >= 2:
        mean = sum(rtts) / len(rtts)
        jitter = round(math.sqrt(sum((x - mean) ** 2 for x in rtts)
                                / len(rtts)), 2)
    ok = fails == 0
    return {"rtt_ms": rtt, "loss_pct": loss, "jitter_ms": jitter, "ok": ok,
            "detail": None if ok else (detail or "all CONNECT attempts failed")}


def socks5_http_get(socks_port: int, host: str, path: str = "/",
                    proxy_host: str = "127.0.0.1", timeout_s: float = 8.0,
                    port: int = 80) -> str | None:
    """Minimal HTTP GET through the SOCKS5 tunnel — used for the activation
    receipt (exit IP check). Returns response body or None."""
    try:
        s = _socks5_connect(proxy_host, socks_port, host, port, timeout_s)
        s.settimeout(timeout_s)
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: TunnelGuard-receipt/1.0\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n").encode())
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
        s.close()
        raw = b"".join(chunks).decode("utf-8", "replace")
        head, _, body = raw.partition("\r\n\r\n")
        status_line = head.split("\r\n")[0] if head else ""
        if " 200 " not in f"{status_line} ":
            return None
        return body.strip() or None
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------ scoring
def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def score_sample(rtt_ms: float | None, loss_pct: float, jitter_ms: float | None,
                 s: dict, recent_switches: int = 0) -> float:
    """Weighted health score 0..100 for one sample."""
    w = {
        "loss": float(s.get("weight_loss", 40)),
        "lat": float(s.get("weight_latency", 30)),
        "jit": float(s.get("weight_jitter", 20)),
        "stab": float(s.get("weight_stability", 10)),
    }
    rtt_ref = max(1.0, float(s.get("rtt_reference_ms", 300)))
    jit_ref = max(1.0, float(s.get("jitter_reference_ms", 50)))

    loss = clamp(loss_pct / 100.0)
    loss_score = (1.0 - loss) * w["loss"]

    if rtt_ms is None:
        lat_score = 0.0
    else:
        lat_score = clamp((rtt_ref - rtt_ms) / rtt_ref) * w["lat"]

    if jitter_ms is None:
        jit_score = w["jit"] * 0.6 if rtt_ms is not None else 0.0
    else:
        jit_score = clamp((jit_ref - jitter_ms) / jit_ref) * w["jit"]

    stab_score = w["stab"] * clamp(1.0 - recent_switches / 3.0)
    return round(loss_score + lat_score + jit_score + stab_score, 2)


# ------------------------------------------------------------------ window
def stats_from_rows(rows: list[dict], s: dict,
                    recent_switches: int = 0) -> dict:
    """Aggregate probe rows (chronological) into window stats + score."""
    if not rows:
        return {"n": 0, "rtt_ms": None, "loss_pct": 100.0,
                "jitter_ms": None, "score": 0.0, "ok": False}
    rtts = [float(r["rtt_ms"]) for r in rows if r.get("rtt_ms") is not None]
    losses = [float(r.get("loss_pct", 100.0)) for r in rows]
    jitters = [float(r["jitter_ms"]) for r in rows
               if r.get("jitter_ms") is not None]
    rtt = sum(rtts) / len(rtts) if rtts else None
    loss = sum(losses) / len(losses) if losses else 100.0
    jit = sum(jitters) / len(jitters) if jitters else None
    sc = score_sample(rtt, loss, jit, s, recent_switches)
    return {"n": len(rows), "rtt_ms": rtt, "loss_pct": loss,
            "jitter_ms": jit, "score": sc, "ok": loss < s["loss_threshold_pct"]}


class WindowStats:
    """Rolling window over probe rows for one tunnel."""

    def __init__(self, seconds: float = 60.0):
        self.seconds = seconds
        self._rows: list[dict] = []
        self._lock = threading.Lock()

    def add(self, row: dict) -> None:
        with self._lock:
            self._rows.append(row)
            cut = time.time() - self.seconds
            self._rows = [r for r in self._rows if r["ts"] >= cut]

    def snapshot(self) -> dict:
        with self._lock:
            rows = list(self._rows)
        if not rows:
            return {"n": 0, "rtt_ms": None, "loss_pct": 100.0,
                    "jitter_ms": None, "score": 0.0, "ok": False}
        rtts = [r["rtt_ms"] for r in rows if r.get("rtt_ms") is not None]
        losses = [float(r.get("loss_pct", 100.0)) for r in rows]
        jitters = [r["jitter_ms"] for r in rows if r.get("jitter_ms") is not None]
        rtt = sum(rtts) / len(rtts) if rtts else None
        loss = sum(losses) / len(losses) if losses else 100.0
        jit = sum(jitters) / len(jitters) if jitters else None
        from . import db as dbm
        s = dbm.get_settings()
        recent_sw = _recent_switches()
        sc = score_sample(rtt, loss, jit, s, recent_sw)
        return {"n": len(rows), "rtt_ms": rtt, "loss_pct": loss,
                "jitter_ms": jit, "score": sc, "ok": loss < s["loss_threshold_pct"]}


def _recent_switches() -> int:
    try:
        from . import failover
        return failover.recent_switch_count()
    except Exception:
        return 0


# ------------------------------------------------------------------ iperf3
def iperf_cycle(target: str, duration_s: int = 5,
                reverse: bool = True) -> dict | None:
    """Optional iperf3 bandwidth bench. Returns Mbps or None on failure."""
    binp = shutil.which("iperf3")
    if not binp:
        return None
    cmd = [binp, "-c", target, "-t", str(duration_s), "-J", "--connect-timeout", "3000"]
    if reverse:
        cmd.append("-R")
    try:
        cp = _run(cmd, timeout=duration_s + 15)
        import json as _json
        data = _json.loads(cp.stdout)
        sums = data.get("end", {}).get("sum_received") or data.get("end", {}).get("sum_sent")
        return {"mbps": round(sums["bits_per_second"] / 1e6, 2)} if sums else None
    except (subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return None


def validate_settings_numbers(s: dict) -> list[str]:
    """Sanity-check tunables; returns human-readable problems (honest limits)."""
    problems = []
    if not 1 <= int(s.get("probe_interval_s", 3)) <= 300:
        problems.append("probe_interval_s must be 1..300")
    if int(s.get("fail_threshold", 3)) < 1:
        problems.append("fail_threshold must be >= 1 (aggressive values cause flapping)")
    if int(s.get("cooldown_s", 60)) < 10:
        problems.append("cooldown_s < 10s risks route churn / flapping")
    if float(s.get("loss_threshold_pct", 50)) < 10:
        problems.append("loss_threshold_pct < 10% is too twitchy on real networks")
    wsum = sum(float(s.get(k, 0)) for k in
               ("weight_loss", "weight_latency", "weight_jitter", "weight_stability"))
    if abs(wsum - 100.0) > 0.01:
        problems.append(f"scoring weights sum to {wsum}, expected 100")
    return problems
