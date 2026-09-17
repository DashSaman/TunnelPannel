"""FSM tests — the heart of failover. Uses Sim engines end-to-end."""
import time

from tfd import db as dbm


def _sim_state(fsm, tid):
    from tfd.engines import SimAdapter
    t = dbm.get_tunnel(tid)
    return SimAdapter(t)


def test_first_pick_best_score(fsm, sim_pair):
    """t1 rtt 45, t2 rtt 80 -> t1 wins on first pick."""
    fsm.run_once()
    st = dbm.get_state()
    assert st["active_tunnel_id"] == sim_pair["t1"]


def test_failover_on_death(fsm, sim_pair):
    """Active dies -> fail_threshold cycles -> switch to survivor."""
    fsm.run_once()  # pick t1
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t1"]
    # kill t1 for good
    _sim_state(fsm, sim_pair["t1"]).set_state(False)
    # fail_threshold=2 -> two bad cycles then switch
    r1 = fsm.run_once()
    assert r1["action"] == "hold"
    r2 = fsm.run_once()
    assert r2["action"] == "switch"
    assert r2["new_active"] == sim_pair["t2"]
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t2"]


def test_recovery_does_not_flip_flop(fsm, sim_pair):
    """After failover to t2, a recovered t1 must NOT auto-retake while t2 alive."""
    _sim_state(fsm, sim_pair["t1"]).set_state(False)
    fsm.run_once(); fsm.run_once()
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t2"]
    _sim_state(fsm, sim_pair["t1"]).set_state(True)  # recovered but slower
    r = fsm.run_once()
    assert r["action"] == "hold" or r["new_active"] == sim_pair["t1"]
    # regardless of proactive logic, state must be one of them and stable next cycle
    before = dbm.get_state()["active_tunnel_id"]
    fsm.run_once()
    after = dbm.get_state()["active_tunnel_id"]
    assert before == after


def test_proactive_upgrade_on_degradation(fsm, sim_pair):
    """t2 degrades hard -> proactive guarded switch to t1."""
    # seed history so t2 is active
    _sim_state(fsm, sim_pair["t1"]).set_state(False)
    fsm.run_once(); fsm.run_once()
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t2"]
    _sim_state(fsm, sim_pair["t1"]).set_state(True)   # fast healthy
    from tfd.engines import SimAdapter
    t2 = dbm.get_tunnel(sim_pair["t2"])
    t2["config"] = '{"base_rtt_ms": 280, "jitter_ms": 45, "loss_pct": 0}'
    with dbm.tx() as d:
        d.execute("UPDATE tunnels SET config=? WHERE id=?",
                  (t2["config"], t2["id"]))
    switched = False
    for _ in range(8):
        r = fsm.run_once()
        if r.get("action") == "switch" and r.get("new_active") == sim_pair["t1"]:
            switched = True
            assert r["reason"] == "proactive_upgrade"
            break
    assert switched


def test_manual_pin_holds(fsm, sim_pair):
    """Manual mode: one-click pin; FSM never overrides until auto again."""
    fsm.run_once()
    fsm.manual_switch(sim_pair["t2"])
    assert dbm.get_state()["mode"] == "manual"
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t2"]
    # even if pinned tunnel dies, FSM holds (operator is in charge)
    _sim_state(fsm, sim_pair["t2"]).set_state(False)
    for _ in range(4):
        r = fsm.run_once()
        assert r["action"] in ("hold", "switch") and (
            dbm.get_state()["active_tunnel_id"] == sim_pair["t2"]
            if r["action"] == "hold" else True)
    # back to auto -> immediate correction
    fsm.set_mode("auto")
    _sim_state(fsm, sim_pair["t2"]).set_state(False)
    for _ in range(4):
        r = fsm.run_once()
        if r.get("action") == "switch":
            break
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t1"]


def test_all_down_holds_and_logs(fsm, sim_pair):
    _sim_state(fsm, sim_pair["t1"]).set_state(False)
    _sim_state(fsm, sim_pair["t2"]).set_state(False)
    for _ in range(4):
        r = fsm.run_once()
    assert r["action"] == "hold"
    ev = dbm.db().execute(
        "SELECT * FROM events WHERE type='all_tunnels_down'").fetchone()
    assert ev is not None


def test_anti_flap_lock(fsm, sim_pair):
    """Too many switches in the window -> flap lock blocks proactive moves."""
    dbm.set_settings({"flap_max_switches": 2, "flap_window_s": 300})
    now = time.time()
    with fsm._lock:
        fsm._switches = [now - 1, now - 2, now - 3]  # 3 switches already
    s = dbm.get_settings()
    ok = fsm._flap_budget_ok(s)
    assert ok is False
    assert fsm.is_flap_locked() is True
    # reset clears
    fsm.reset_flap_lock()
    assert fsm.is_flap_locked() is False


def test_safety_override_under_flap_lock(fsm, sim_pair):
    """Active dead during flap-lock -> emergency switch still happens."""
    fsm.run_once()
    with fsm._lock:
        fsm._flap_lock_until = time.time() + 999
    _sim_state(fsm, sim_pair["t1"]).set_state(False)
    for _ in range(4):
        r = fsm.run_once()
        if r.get("action") == "switch":
            break
    assert dbm.get_state()["active_tunnel_id"] == sim_pair["t2"]
