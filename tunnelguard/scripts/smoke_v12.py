#!/usr/bin/env python3
"""Smoke: boot the real API, login, check /api/engines catalog + wizard
batch validation for the two new engines (paqet / hajsaman)."""
import json
import time
import os
import subprocess
import sys
import time
import urllib.request

os.environ.setdefault("TF_DATA_DIR", "/tmp/tg-smoke")
os.environ.setdefault("TF_SIM_MODE", "0")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from fastapi.testclient import TestClient  # noqa: E402
from tfd.api import app  # noqa: E402
from tfd import db as dbm  # noqa: E402

dbm.init()
c = TestClient(app)

# login (bootstrap admin)
r = c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
if r.status_code == 401:
    from tfd import security
    with dbm.tx() as d:
        d.execute("INSERT OR REPLACE INTO users(username,pw_hash,role,"
                  "created_at) VALUES(?,?,?,?)",
                  ("admin", security.hash_password("admin"), "admin",
                   time.time()))
    r = c.post("/api/auth/login", json={"username": "admin",
                                        "password": "admin"})
assert r.status_code == 200, r.text
tok = r.json()["token"]
H = {"Authorization": f"Bearer {tok}"}

engines = c.get("/api/engines", headers=H).json()["engines"]
print("catalog:", sorted(engines.keys()))
assert "paqet" in engines and "hajsaman" in engines
assert engines["paqet"]["kind"] == "proxy"
assert engines["hajsaman"]["kind"] == "kernel"
assert not engines["hajsaman"].get("pending"), "pending flag must be gone"
print("paqet fields:", engines["paqet"]["fields"][:6], "...")
print("hajsaman fields:", engines["hajsaman"]["fields"][:6], "...")

# batch create with paqet: precheck must fail honestly (no root/binary here)
spec = {"name": "smoke-paqet", "engine": "paqet", "iface": "pq90",
        "local_ip": "", "remote_ip": "", "remote_host": "198.51.100.9",
        "mtu": 1350, "remote_ssh": None,
        "config": {"role": "client"}}
r = c.post("/api/tunnels/batch", headers=H,
           json={"tunnels": [spec], "activate": True})
rep = r.json()["results"][0]
print("batch paqet ok=", rep["ok"])
assert rep["ok"] is False and rep["steps"][0]["step"] == "precheck"
print("  honest precheck:", rep["steps"][0]["detail"][:90], "...")

# hajsaman batch: auto mode -> native precheck (honest missing keys)
spec2 = {"name": "smoke-hjs", "engine": "hajsaman", "iface": "tfh90",
         "local_ip": "", "remote_ip": "", "remote_host": "198.51.100.9",
         "mtu": 1420, "remote_ssh": None, "config": {}}
r2 = c.post("/api/tunnels/batch", headers=H,
            json={"tunnels": [spec2], "activate": True})
rep2 = r2.json()["results"][0]
print("batch hajsaman ok=", rep2["ok"])
assert rep2["ok"] is False
print("  honest precheck:", rep2["steps"][0]["detail"][:90], "...")

print("\nSMOKE PASS — catalog + honest wizard prechecks verified on live API")
