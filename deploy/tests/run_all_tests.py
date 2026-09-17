#!/usr/bin/env python3
"""Run ALL 77 method tests inside the mtf-panel container -> receipts in DB.
Writes progress to /opt/multitunnel/data/test_progress.json for polling."""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, "/opt/multitunnel/engine")
from mtf import state                                    # noqa: E402
from mtf.registry import load_registry                   # noqa: E402
from mtf_userspace import test_method, RUNNERS           # noqa: E402

BASE = "/opt/multitunnel"
PROG = f"{BASE}/data/test_progress.json"

KERNEL_LIKE = {
    "WIREGUARD", "GRE", "GRETAP", "SIT_6IN4", "IPIP", "VXLAN",
    "IP6GRE", "IP6GRETAP", "VTI", "VTI6", "L2TP_IPSEC", "OPENVPN",
    "IKEV2_IPSEC", "SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS",
    "SSH_REMOTE_FORWARD", "SSH_TUN_L3", "SSH_TAP_L2", "AUTOSSH_REVERSE",
    "GRE_OVER_WIREGUARD", "GRE_OVER_SSH", "SIT_OVER_SSH",
    "GRE_OVER_GOST", "GRETAP_OVER_GOST", "SIT_OVER_GOST",
    "HAJSAMAN_SIT", "HAJSAMAN_WG", "HAJSAMAN_FULL",
}
GOST_FAM = {m.id: "GOST" for m in load_registry() if m.set == "GOST_METHODS"}


def write_progress(d):
    tmp = PROG + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, ensure_ascii=False)
    os.replace(tmp, PROG)


def run_kernel(mid):
    p = subprocess.run(["bash", f"{BASE}/engine/mtf_kernel.sh", mid],
                       capture_output=True, text=True, timeout=240)
    if p.returncode == 0:
        try:
            ev = json.loads(p.stdout or "{}")
        except Exception:
            ev = {"raw": p.stdout[-400:]}
        return "PASS", ev
    try:
        ev = json.loads(p.stdout or "{}")
    except Exception:
        ev = {"err": (p.stdout + p.stderr)[-500:]}
    return "FAIL", ev


def main():
    state.init_db()
    methods = load_registry()
    fam = {m.id: m.set.replace("_METHODS", "").replace("KERNEL_BASE", "KERNEL")
           for m in methods}
    prog = {"total": len(methods), "done": 0, "results": {}, "started": time.time()}
    write_progress(prog)
    for m in methods:
        mid = m.id
        t0 = time.time()
        try:
            if mid in KERNEL_LIKE:
                verdict, ev = run_kernel(mid)
            elif mid in GOST_FAM:
                verdict, ev = test_method(mid, "GOST")
            else:
                verdict, ev = test_method(mid, fam[mid])
        except Exception as e:
            verdict, ev = "FAIL", {"exception": str(e)[:300]}
        ev = dict(ev or {})
        ev["duration_ms"] = int((time.time() - t0) * 1000)
        state.save_receipt(mid, verdict, ev)
        prog["results"][mid] = {"verdict": verdict, "ms": ev["duration_ms"]}
        prog["done"] += 1
        prog["finished_at"] = time.time()
        write_progress(prog)
    summary = {}
    for r in prog["results"].values():
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    state.event("info", "tests", f"ALL {len(methods)} DONE: {summary}")
    write_progress(prog)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
