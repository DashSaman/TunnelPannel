"""TunnelGuard test suite — shared fixtures.

The sandbox/CI environment has no CAP_NET_ADMIN, so:
 - real kernel engines are exercised only via *recording executors* (unit);
 - the full pipeline (probe -> score -> FSM -> routing hooks -> API) runs
   end-to-end on Sim engines;
 - real-engine receipts come from scripts/selftest.py on the actual server.
"""
import os
import sys
import tempfile

os.environ.setdefault("TF_DATA_DIR", tempfile.mkdtemp(prefix="tg-test-"))
os.environ.setdefault("TF_SIM_MODE", "0")  # tests toggle per-case
_tmp_etc = tempfile.mkdtemp(prefix="tg-etc-")
os.environ.setdefault("TF_ETC_DIR", _tmp_etc)
os.environ.setdefault("TF_WG_CONF_DIR", os.path.join(_tmp_etc, "wireguard"))
os.environ.setdefault("TF_SWANCTL_DIR", os.path.join(_tmp_etc, "swanctl"))
os.environ.setdefault("TF_NFT_CONF", os.path.join(_tmp_etc, "nft.conf"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest  # noqa: E402


@pytest.fixture()
def fresh_db():
    """Completely fresh DB file per test (deterministic, no cross-test state)."""
    from tfd import config, db as dbm
    try:
        dbm._conn is not None and dbm._conn.close()
    except Exception:
        pass
    dbm._conn = None
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(str(config.DB_PATH) + suffix)
        except FileNotFoundError:
            pass
    dbm.init()
    from tfd.engines import SimAdapter
    with SimAdapter._lock:
        SimAdapter._states.clear()
    yield dbm
    try:
        dbm._conn.close()
    finally:
        dbm._conn = None


@pytest.fixture()
def sim_pair(fresh_db):
    """Two healthy sim tunnels + sim_mode on + fast FSM knobs."""
    from tfd import config, db as dbm
    dbm.set_settings({"sim_mode": True, "fail_threshold": 2,
                      "cooldown_s": 0, "hysteresis_margin": 0.5,
                      "proactive_k": 2, "probe_interval_s": 1})
    t1 = dbm.db().execute(
        "INSERT INTO tunnels(name,engine,iface,local_ip,remote_ip,remote_host,"
        "mtu,config,remote_ssh,enabled,priority,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("primary", "sim", "tfA", "10.10.10.1", "10.10.10.2", "198.51.100.2",
         1420, '{"base_rtt_ms": 45, "jitter_ms": 4, "loss_pct": 0}', "",
         1, 1, 1.0)).lastrowid
    t2 = dbm.db().execute(
        "INSERT INTO tunnels(name,engine,iface,local_ip,remote_ip,remote_host,"
        "mtu,config,remote_ssh,enabled,priority,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        ("backup", "sim", "tfB", "10.10.11.1", "10.10.11.2", "203.0.113.2",
         1420, '{"base_rtt_ms": 80, "jitter_ms": 6, "loss_pct": 0}', "",
         1, 2, 1.0)).lastrowid
    fresh_db.db().commit()
    yield {"t1": t1, "t2": t2, "dbm": dbm}


@pytest.fixture()
def fsm(sim_pair):
    from tfd.failover import engine
    with engine._lock:
        engine._switches.clear()
        engine._better_streak.clear()
        engine._streaks.clear()
        engine._flap_lock_until = 0.0
    yield engine
    with engine._lock:
        engine._switches.clear()
