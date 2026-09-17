#!/usr/bin/env python3
"""MTF remote installer — deploy & verify tunnel methods on REAL servers via SSH.

The panel host stays engine-only: harness files are pushed to the target server,
the tunnel is built there (kernel netns harness or userspace loopback pair),
and the verdict is stored per-server in data/deployments.json.

API:
  run_install(host, port, user, pw, mids)  -> background thread (JOB live status)
  status()                                 -> per-host deployment book
"""
import json
import os
import threading
import time

import paramiko

from .registry import load_registry

BASE = "/opt/multitunnel"
DATA = f"{BASE}/data"
DEPLOY_FILE = f"{DATA}/deployments.json"
ENGINE_DIR = f"{BASE}/engine"
REMOTE_DIR = "/root/.mtf"

JOB = {"running": False, "target": None, "done": 0, "total": 0,
       "current": None, "ok": 0, "fail": 0, "err": "", "ts": None}

_lock = threading.Lock()

KERNEL_LIKE = {
    "WIREGUARD", "GRE", "GRETAP", "SIT_6IN4", "IPIP", "VXLAN",
    "IP6GRE", "IP6GRETAP", "VTI", "VTI6", "L2TP_IPSEC", "OPENVPN",
    "IKEV2_IPSEC", "SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS",
    "SSH_REMOTE_FORWARD", "SSH_TUN_L3", "SSH_TAP_L2", "AUTOSSH_REVERSE",
    "GRE_OVER_WIREGUARD", "GRE_OVER_SSH", "SIT_OVER_SSH",
    "GRE_OVER_GOST", "GRETAP_OVER_GOST", "SIT_OVER_GOST",
    "HAJSAMAN_SIT", "HAJSAMAN_WG", "HAJSAMAN_FULL",
}


def _load():
    try:
        with open(DEPLOY_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(book):
    tmp = DEPLOY_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(book, f, ensure_ascii=False, indent=1)
    os.replace(tmp, DEPLOY_FILE)


def status():
    return _load()


def _client(host, port, user, pw):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username=user, password=pw, timeout=25,
              banner_timeout=25, auth_timeout=25,
              look_for_keys=False, allow_agent=False)
    return c


def _run(c, cmd, timeout=240):
    _, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    rc = out.channel.recv_exit_status()
    return rc, o, e


def _prep(c):
    """Push harness files + ensure minimal deps (jq, wireguard-tools) on target."""
    rc, o, e = _run(c,
        "export DEBIAN_FRONTEND=noninteractive; "
        "mkdir -p " + REMOTE_DIR + "; "
        "command -v jq >/dev/null || apt-get update -qq >/dev/null 2>&1; "
        "command -v jq >/dev/null || apt-get install -y -qq jq >/dev/null 2>&1; "
        "command -v wg >/dev/null || apt-get install -y -qq wireguard-tools >/dev/null 2>&1; "
        "echo PREP-DONE", timeout=420)
    sftp = c.open_sftp()
    for f in ("mtf_kernel.sh", "mtf_userspace.py"):
        sftp.put(os.path.join(ENGINE_DIR, f), f"{REMOTE_DIR}/{f}")
    sftp.close()
    _run(c, f"chmod +x {REMOTE_DIR}/mtf_kernel.sh")
    return "PREP-DONE" in (o + e)


def _parse_json_tail(o):
    try:
        i, j = o.index("{"), o.rindex("}")
        return json.loads(o[i:j + 1])
    except Exception:
        return None


def _test_method(c, mid, fam):
    """Run one method's harness on the target server; return (verdict, evidence)."""
    if mid in KERNEL_LIKE:
        rc, o, e = _run(c, f"bash {REMOTE_DIR}/mtf_kernel.sh {mid} 2>&1", timeout=280)
    else:
        rc, o, e = _run(c,
            f"test -d {BASE}/bin || echo NOBIN; "
            f"cd {REMOTE_DIR} && python3 {REMOTE_DIR}/mtf_userspace.py {mid} {fam} 2>&1 | tail -c 4000",
            timeout=280)
        if "NOBIN" in o:
            return "FAIL", [f"target has no {BASE}/bin (tunnel binaries) — install them first"]
    j = _parse_json_tail(o)
    if j:
        evd = [str(x)[:160] for x in (j.get("evidence") or [])][:6]
        verdict = j.get("verdict") or ("PASS" if rc == 0 else "FAIL")
    else:
        evd = [(o or e)[-260:]]
        verdict = "PASS" if rc == 0 else "FAIL"
    # honesty gate: never report PASS when the evidence shows the binary was
    # missing/corrupt or the harness hit an exception
    joined = " ".join(evd).lower()
    if verdict == "PASS" and any(
            k in joined for k in ("exception:", "no such file", "exec format error",
                                  "missing", "not found", "command not found")):
        return "FAIL", evd
    if verdict == "PASS" and any(k in joined for k in ("-> 000", "curl: (", "refused", "timeout")):
        return "PARTIAL", evd
    return verdict, evd


def run_install(host, port, user, pw, mids):
    """Background job: prep target, then install+verify each method there."""
    with _lock:
        if JOB["running"]:
            return False
        JOB.update(running=True, target=host, done=0, total=len(mids),
                   current=None, ok=0, fail=0, err="", ts=time.time())
    try:
        c = _client(host, port, user, pw)
        try:
            JOB["current"] = "PREP"
            if not _prep(c):
                JOB["err"] = "target prep failed (harness upload/deps)"
                return False
            fam = {m.id: m.set.replace("_METHODS", "").replace("KERNEL_BASE", "KERNEL")
                   for m in load_registry()}
            book = _load()
            hostbook = book.get(host, {"ts": time.time(), "results": {}})
            for mid in mids:
                JOB["current"] = mid
                t0 = time.time()
                try:
                    verdict, evd = _test_method(c, mid, fam.get(mid, "UNKNOWN"))
                except Exception as ex:
                    verdict, evd = "FAIL", [f"exception: {str(ex)[:200]}"]
                hostbook["results"][mid] = {
                    "verdict": verdict,
                    "evidence": evd,
                    "ms": int((time.time() - t0) * 1000),
                    "ts": time.time(),
                }
                hostbook["ts"] = time.time()
                book[host] = hostbook
                _save(book)
                JOB["done"] += 1
                if verdict == "PASS":
                    JOB["ok"] += 1
                elif verdict == "FAIL":
                    JOB["fail"] += 1
            JOB["current"] = None
        finally:
            try:
                c.close()
            except Exception:
                pass
        return True
    except Exception as ex:
        JOB["err"] = str(ex)[:300]
        return False
    finally:
        JOB["running"] = False
