#!/usr/bin/env python3
"""HedioumAdapter end-to-end lifecycle test against the lab foreign node.

Prereq: scripts/hedioum_lab/start_lab.sh started (foreign on :12222).
The adapter itself spawns/owns its own hub process (standalone mode) on
socks port 40011 — full render -> precheck -> up -> probe -> receipt -> down.

Run:  python3 scripts/run_hedioum_e2e.py
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("TF_DATA_DIR", "/tmp/tg-hedioum-e2e")
os.environ["TF_HEDIOUM_CONF"] = "/tmp/tg-hedioum-e2e/etc-hedioum.json"

from tfd.engines.hedioum import HedioumAdapter, CONFIG_PATH  # noqa: E402
from tfd import db as _dbm  # noqa: E402

_dbm.init()

LAB = "/home/z/my-project/scripts/hedioum_lab"
BINARY = os.path.join(LAB, "hedioum-tunnel")


def main() -> int:
    token = open(os.path.join(LAB, "token.txt")).read().strip()
    tunnel = {
        "id": 7,
        "name": "e2e-lab-foreign",
        "engine": "hedioum",
        "iface": "hedioom7",
        "remote_host": "127.0.0.1",
        "config": json.dumps({
            "pairing_token": "",          # manual fields this time
            "foreign_ip": "127.0.0.1",
            "foreign_port": 12222,
            "auth_token": token,
            "mimic": "ssh",
            "socks_port": 40011,
            "min_connections": 2,
            "max_connections": 4,
            "bandwidth_limit_mbps": 8,
            "bandwidth_jitter_mbps": 2,
            "standalone": True,
            "binary_path": BINARY,
        }),
    }

    a = HedioumAdapter(tunnel)

    print("== 1. render (merged hub config) ==")
    artifacts = a.render()
    merged = json.loads(artifacts[CONFIG_PATH])
    assert merged["role"] == "iran", merged.get("role")
    assert len(merged["foreign_nodes"]) == 1
    assert merged["foreign_nodes"][0]["alias"] == "e2e-lab-foreign"
    assert merged["foreign_nodes"][0]["local_socks_port"] == 40011
    print("   ok:", json.dumps(merged["foreign_nodes"][0])[:120])

    print("== 2. precheck ==")
    problems = a.precheck()
    # the honest SOCKS-only note is expected; everything else must be clean
    hard = [p for p in problems if "SOCKS-only" not in p]
    assert not hard, hard
    print("   ok (only the honest socks-only note):", problems)

    print("== 3. up (standalone hub on :40011) ==")
    cmds = a.up()
    for c in cmds:
        print("   ", c)

    print("== 4. status ==")
    st = a.status()
    assert st["up"], st
    print("   ok:", st)

    print("== 5. through-tunnel probe (the FSM signal) ==")
    row = a._probe_cycle()
    assert row["ok"], row
    print(f"   ok rtt={row['rtt_ms']}ms loss={row['loss_pct']}%")

    print("== 6. exit-IP receipt ==")
    rec = a.receipt()
    assert rec["through_tunnel"], rec
    print("   ok exit_ip:", rec["exit_ip"])

    print("== 7. down ==")
    for c in a.down():
        print("   ", c)
    st2 = a.status()
    assert not st2["up"], st2
    print("   ok: tunnel down, socks closed")

    print("\nE2E PASS — full adapter lifecycle verified against a real "
          "Hedioum foreign node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
