#!/usr/bin/env python3
"""MTF probe engine — SSH reachability tests between servers + tunnel recommendations.

Flow:
  1. Concurrent SSH login to every server given by the user (IP, port, user, pass).
  2. Pairwise quality: from each server, ping every other server (ICMP),
     with TCP-connect fallback (curl time_connect to the SSH port).
  3. Results saved to /opt/multitunnel/data/probe_last.json (NO credentials stored).
  4. build_recommendations() maps measured quality -> best tunnel methods + reasons (fa/en).
"""
import concurrent.futures as cf
import json
import os
import re
import threading
import time

BASE = "/opt/multitunnel"
DATA = os.path.join(BASE, "data")
PROBE_PATH = os.path.join(DATA, "probe_last.json")

JOB = {"running": False, "started": 0, "phase": "", "progress": "", "n_servers": 0}
_lock = threading.Lock()


# ---------------------------------------------------------------- SSH helpers
def _ssh(host, port, user, password, timeout=12):
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    t0 = time.time()
    cli.connect(host, port=int(port or 22), username=user or "root",
                password=password or "", timeout=timeout, banner_timeout=timeout,
                auth_timeout=timeout, look_for_keys=False, allow_agent=False)
    return cli, (time.time() - t0) * 1000.0


def _run(cli, cmd, timeout=15):
    _, o, e = cli.exec_command(cmd, timeout=timeout)
    out = o.read().decode("utf-8", "replace")
    err = e.read().decode("utf-8", "replace")
    return out, err


def _parse_ping(out: str):
    """-> (loss_pct, avg_rtt, mdev_jitter) ; None when not parseable."""
    loss, rtt, jit = None, None, None
    m = re.search(r"([\d.]+)%\s*packet loss", out)
    if m:
        loss = float(m.group(1))
    m2 = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/([\d.]+)", out)
    if m2:
        rtt = float(m2.group(1))
        jit = float(m2.group(2))
    return loss, rtt, jit


# ------------------------------------------------------------ single server
def _probe_one(s: dict) -> dict:
    out = {"name": s.get("name") or s["host"], "host": s["host"],
           "ssh_port": int(s.get("ssh_port") or 22), "ok": False,
           "ssh_ms": None, "kernel": "", "os": "", "uptime": "", "ips": [],
           "err": ""}
    try:
        cli, ms = _ssh(s["host"], s.get("ssh_port"), s.get("username"), s.get("password"))
        out["ssh_ms"] = round(ms, 1)
        script = ("uname -r; "
                  ". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\"; "
                  "uptime -p 2>/dev/null | head -1; "
                  "ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\\n' ' '")
        o, _e = _run(cli, script, timeout=12)
        lines = [l.strip() for l in o.splitlines() if l.strip()]
        if len(lines) > 0:
            out["kernel"] = lines[0][:60]
        if len(lines) > 1:
            out["os"] = lines[1][:80]
        if len(lines) > 2:
            out["uptime"] = lines[2][:60]
        if len(lines) > 3:
            out["ips"] = [x for x in lines[3].split() if x][:4]
        out["ok"] = True
        try:
            cli.close()
        except Exception:
            pass
    except Exception as ex:
        out["err"] = str(ex)[:220]
    return out


# ---------------------------------------------------------------- pairwise
def _probe_pair(a: dict, b: dict, infos: dict) -> dict:
    res = {"from": a["host"], "from_name": a.get("name") or a["host"],
           "to": b["host"], "to_name": b.get("name") or b["host"],
           "ok": False, "via": "", "loss_pct": None, "rtt_ms": None,
           "jitter_ms": None, "err": ""}
    if not infos.get(a["host"], {}).get("ok"):
        res["err"] = "source ssh unreachable"
        return res
    cli = None
    try:
        cli, _ = _ssh(a["host"], a.get("ssh_port"), a.get("username"), a.get("password"))
        o, _e = _run(cli, f"ping -c 3 -W 2 {b['host']} 2>&1", timeout=15)
        loss, rtt, jit = _parse_ping(o)
        if loss is not None and loss < 100 and rtt is not None:
            res.update(ok=True, via="icmp", loss_pct=loss, rtt_ms=rtt, jitter_ms=jit)
        else:
            # TCP fallback: connect to B's SSH port from A, measure connect time
            port = int(b.get("ssh_port") or 22)
            o2, _e2 = _run(
                cli,
                f"curl -s -o /dev/null --connect-timeout 3 --max-time 4 "
                f"-w '%{{time_connect}}' telnet://{b['host']}:{port} 2>/dev/null; echo",
                timeout=12)
            v = (o2 or "").strip().splitlines()
            v = v[-1].strip() if v else ""
            if v and re.match(r"^\d*\.?\d+$", v) and float(v) > 0:
                res.update(ok=True, via="tcp", loss_pct=0.0,
                           rtt_ms=round(float(v) * 1000.0, 1),
                           jitter_ms=None)
            else:
                res.update(via="icmp", loss_pct=100.0,
                           err="ping 100% loss + tcp connect failed")
    except Exception as ex:
        res["err"] = str(ex)[:200]
    finally:
        try:
            if cli:
                cli.close()
        except Exception:
            pass
    return res


# ------------------------------------------------------------------- job
def run_probe(servers: list):
    with _lock:
        if JOB["running"]:
            return {"ok": False, "error": "already running"}
        JOB.update(running=True, started=time.time(), phase="ssh",
                   progress=f"0/{len(servers)}", n_servers=len(servers))
    try:
        infos = {}
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(_probe_one, s): s for s in servers}
            done = 0
            for f in cf.as_completed(futs):
                s = futs[f]
                infos[s["host"]] = f.result()
                done += 1
                JOB.update(phase="ssh", progress=f"{done}/{len(servers)}")

        results = {"ts": time.time(), "servers": [infos[s["host"]] for s in servers],
                   "matrix": []}
        pairs = [(a, b) for a in servers for b in servers if a["host"] != b["host"]]
        JOB.update(phase="pairs", progress=f"0/{len(pairs)}")
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(_probe_pair, a, b, infos): (a, b) for a, b in pairs}
            done = 0
            for f in cf.as_completed(futs):
                a, b = futs[f]
                results["matrix"].append(f.result())
                done += 1
                JOB.update(phase="pairs", progress=f"{done}/{len(pairs)}")

        os.makedirs(DATA, exist_ok=True)
        tmp = PROBE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fp:
            json.dump(results, fp, ensure_ascii=False)
        os.replace(tmp, PROBE_PATH)
        JOB.update(running=False, phase="done", progress="complete")
        return {"ok": True}
    except Exception as ex:
        JOB.update(running=False, phase="error", progress=str(ex)[:120])
        return {"ok": False, "error": str(ex)[:200]}


def status() -> dict:
    result = None
    try:
        if os.path.exists(PROBE_PATH):
            with open(PROBE_PATH, encoding="utf-8") as fp:
                result = json.load(fp)
    except Exception:
        result = None
    return {"running": JOB["running"], "phase": JOB["phase"],
            "progress": JOB["progress"], "n_servers": JOB["n_servers"],
            "result": result}


# ------------------------------------------------------- recommendation engine
def _match(prefix: str, ids: list):
    for mid in ids:
        if mid == prefix:
            return mid
    for mid in ids:
        if mid.startswith(prefix):
            return mid
    return None


def _score_pair(p: dict) -> float:
    loss = p.get("loss_pct")
    rtt = p.get("rtt_ms")
    jit = p.get("jitter_ms")
    loss = 100.0 if loss is None else min(float(loss), 100.0)
    rtt = 400.0 if rtt is None else float(rtt)
    jit = 120.0 if jit is None else float(jit)
    score = 100.0 - loss * 1.8 - min(rtt / 8.0, 35.0) - min(jit * 1.2, 20.0)
    return max(0.0, round(score))


def _label(score: float):
    if score >= 85:
        return "عالی / excellent"
    if score >= 65:
        return "خوب / good"
    if score >= 40:
        return "ضعیف / weak"
    return "بد / poor"


def recommend_pair(p: dict, ids: list) -> dict:
    """One directed pair -> quality + ranked method recommendations."""
    score = _score_pair(p)
    loss = p.get("loss_pct")
    rtt = p.get("rtt_ms") or 400.0
    jit = p.get("jitter_ms") or 120.0
    loss = 100.0 if loss is None else float(loss)
    udp_ok = p.get("via") == "icmp" and loss < 60

    recs = []

    def add(fam, bonus, fa, en, tags):
        mid = _match(fam, ids)
        fit = min(99, int(score * 0.92 + bonus))
        recs.append({"method_id": mid, "family": fam, "fit": fit,
                     "why_fa": fa, "why_en": en, "tags": tags})

    # --- condition-driven rules -------------------------------------------
    if score >= 85 and udp_ok:
        add("WIREGUARD", 9,
            "لینک عالی و پایدار — وایرگارد کرنلی بیشترین throughput و کمترین CPU را می‌دهد",
            "Excellent stable link — kernel WireGuard gives max throughput, min overhead",
            ["kernel-L3", "fastest", "udp"])
        add("GRE", 6,
            "لینک تمیز — GRE کرنلی ساده و کم‌سربار برای L3",
            "Clean link — kernel GRE is simple, low-overhead L3",
            ["kernel-L3", "udp"])
        add("IPIP", 4,
            "ساده‌ترین تونل IP-in-IP برای لینک سالم بین دو سرور لینوکسی",
            "Simplest IP-in-IP tunnel for healthy Linux-to-Linux links",
            ["kernel-L3", "udp"])
    if score >= 65:
        add("VLESS_REALITY", 7,
            "TCP/TLS با پوشش reality — پایدار و مقاوم در برابر شنود/فیلترینگ",
            "TCP/TLS with reality camouflage — stable and censorship-resistant",
            ["tcp", "tls", "anti-dpi"])
        add("CHISEL", 4,
            "تونل TCP/Websocket ساده و مطمئن روی هر لینکی که SSH دارد",
            "Simple reliable TCP/WebSocket tunnel over any SSH-capable link",
            ["tcp", "ws"])
    if loss > 10:
        add("HEDIOUM_POOL", 18,
            "لینک پرلاس — هدیوم با پول چندمسیره پکت‌های گم‌شده را جبران می‌کند",
            "Lossy link — Hedioum multipath pool compensates lost packets",
            ["multipath", "anti-loss", "your-pick"])
        add("WATERWALL", 15,
            "لینک پرلاس — WaterWall با دستکاری/تکرار پکت TCP لاس را می‌پوشاند",
            "Lossy link — WaterWall TCP tricks/retransmit hide packet loss",
            ["tcp", "anti-loss"])
        add("PAQET", 14,
            "لینک پرلاس — paqet روی QUIC با بازیابی سریع بهترین ریکاوری را دارد",
            "Lossy link — paqet QUIC with fast retransmit recovers best",
            ["quic", "anti-loss", "your-pick"])
        add("RATHOLE", 6,
            "لینک ناپایدار — rathole با mux روی TCP اتصال را نگه می‌دارد",
            "Unstable link — rathole TCP multiplexing keeps the connection alive",
            ["tcp", "mux"])
    if jit > 60:
        add("HYSTERIA2", 12,
            "جیتر بالا — hysteria2 روی QUIC با کنترل ازدحام Brave سریع‌ترین گزینه است",
            "High jitter — hysteria2 over QUIC with brutal CC is the fastest option",
            ["quic", "udp"])
        add("PAQET", 10,
            "جیتر بالا — QUIC paqet با کنترل ازدحام مدرن جیتر را بهتر تحمل می‌کند",
            "High jitter — paqet QUIC modern congestion control tolerates jitter",
            ["quic", "your-pick"])
        add("WSTUNNEL", 5,
            "جیتر بالا — wstunnel روی websocket+TLS بافر می‌کند و پرش‌ها را می‌پوشاند",
            "High jitter — wstunnel websocket+TLS buffers out the spikes",
            ["tcp", "ws", "tls"])
    if not udp_ok or loss >= 90:
        add("CHISEL", 12,
            "ICMP/UDP مشکل‌دار به‌نظر می‌رسد — چیزل روی TCP خالص کار می‌کند",
            "ICMP/UDP looks blocked — chisel works over pure TCP",
            ["tcp", "udp-block-safe"])
        add("GOST", 9,
            "در صورت بلاک UDP — GOST با wss/TLS روی ۴۴۳ زنده می‌ماند",
            "If UDP is blocked — GOST wss/TLS survives on 443",
            ["tcp", "tls", "443"])

    # --- the three user-picked tunnels, always listed ----------------------
    add("HEDIOUM_POOL", 4,
        "انتخاب شما — تانل هدیوم برای لینک‌های شلوغ/ناپایدار طراحی شده (پول چندمسیره)",
        "Your pick — Hedioum built for congested/unstable links (multipath pool)",
        ["your-pick"])
    add("HAJSAMAN", 2,
        "انتخاب شما — تانل حاج‌سامان سبک و سریع روی لینک‌های پایدار TCP",
        "Your pick — HajSaman lightweight and fast on stable TCP links",
        ["your-pick"])
    add("PAQET", 2,
        "انتخاب شما — paqet روی QUIC برای لینک‌های پرلاس/پرجیتر",
        "Your pick — paqet over QUIC for lossy/jittery links",
        ["your-pick", "quic"])

    # dedupe by family, keep highest fit, sort desc
    best = {}
    for r in recs:
        if r["family"] not in best or r["fit"] > best[r["family"]]["fit"]:
            best[r["family"]] = r
    out = sorted(best.values(), key=lambda r: -r["fit"])[:8]
    for i, r in enumerate(out, 1):
        r["rank"] = i
    return {"from": p.get("from_name") or p.get("from"), "to": p.get("to_name") or p.get("to"),
            "from_ip": p.get("from"), "to_ip": p.get("to"),
            "ok": p.get("ok", False), "via": p.get("via"), "loss_pct": p.get("loss_pct"),
            "rtt_ms": p.get("rtt_ms"), "jitter_ms": p.get("jitter_ms"),
            "score": int(score), "label": _label(score),
            "recommendations": out}


def build_recommendations(ids: list) -> dict:
    try:
        with open(PROBE_PATH, encoding="utf-8") as fp:
            probe = json.load(fp)
    except Exception:
        return {"ok": False, "need_probe": True,
                "hint_fa": "اول تست سرورها را اجرا کنید (تب پروب سرورها)",
                "hint_en": "run the server probe first (Servers tab)"}
    matrix = probe.get("matrix") or []
    if not matrix:
        return {"ok": False, "need_probe": True,
                "hint_fa": "برای پیشنهاد، حداقل ۲ سرور لازم است",
                "hint_en": "at least 2 servers needed for recommendations"}
    pairs = [recommend_pair(p, ids) for p in matrix]
    ranked = sorted(pairs, key=lambda p: -p["score"])
    # dedupe reverse duplicates for the "best pair" headline (A->B vs B->A)
    seen, best_pairs = set(), []
    for p in ranked:
        key = tuple(sorted([p["from_ip"], p["to_ip"]]))
        if p["ok"] and key in seen:
            continue
        seen.add(key)
        best_pairs.append(p)
    return {"ok": True, "generated_ts": time.time(),
            "best_pair": best_pairs[0] if best_pairs else None,
            "pairs": pairs}
