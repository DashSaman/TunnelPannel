"""Failover engine tests (P10 §58) — unit_portable tier.

Mandatory matrix: first selection · active fails · thresholds · switch to
backup · recovery threshold · all preemption modes · manual pin ·
maintenance · anti-flap · flap lock · emergency · component repair ·
underlay propagation · diversity warnings · unselected NEVER chosen ·
receipts recorded.
"""
import pytest

from orchestrator.failover import (FailoverController, FailoverPolicy,
                                   MemberRuntime, decide_repair,
                                   diversity_recommendation, diversity_warnings,
                                   propagate_underlay_failure)

pytestmark = pytest.mark.unit_portable


def members(n=3):
    return [MemberRuntime(f"m{i}", f"route-{i}", priority=i + 1) for i in range(n)]


class TestSelectionAndSwitching:
    def test_first_selection_prefers_priority_1(self):
        c = FailoverController(members())
        assert c.active == "m0"

    def test_active_fails_after_threshold_switches_to_backup(self):
        c = FailoverController(members(), FailoverPolicy(failure_threshold=3))
        for _ in range(3):
            c.on_probe("m0", False)
        r = c.decide()
        assert r is not None and r.to == "m1" and r.frm == "m0"
        assert "3 consecutive bad probes" in r.reason
        assert r.actor in ("AUTO", "EMERGENCY")

    def test_single_bad_probe_does_not_switch(self):
        c = FailoverController(members(), FailoverPolicy(failure_threshold=3))
        c.on_probe("m0", False)
        assert c.decide() is None

    def test_unselected_route_never_chosen(self):
        # only m0 and m1 are members; there is no "unselected" id to pick —
        # membership IS the boundary. Even total failure cannot invent a route.
        c = FailoverController(members(2), FailoverPolicy(failure_threshold=2))
        for m in ("m0", "m1"):
            for _ in range(5):
                c.on_probe(m, False)
        assert c.decide() is None or c.active in {"m0", "m1"}

    def test_recovery_threshold_required_for_return(self):
        c = FailoverController(members(), FailoverPolicy(
            failure_threshold=2, recovery_threshold=3, preemption="PREFER_PRIMARY",
            prefer_primary_recovery_s=0, cooldown_s=0))
        for _ in range(2):
            c.on_probe("m0", False)
        c.decide()                                   # switched to m1
        c.on_probe("m0", True)
        c.on_probe("m0", True)                       # only 2 good — below threshold
        assert c.active == "m1"
        c.on_probe("m0", True)                       # 3rd good probe
        r = c.decide()
        assert r is not None and r.to == "m0" and "recovered" in r.reason


class TestPreemptionModes:
    def test_no_preempt_stays_on_backup(self):
        c = FailoverController(members(), FailoverPolicy(
            failure_threshold=1, recovery_threshold=1, preemption="NO_PREEMPT"))
        c.on_probe("m0", False)
        c.decide()                                   # -> m1
        c.on_probe("m0", True)
        assert c.decide() is None and c.active == "m1"

    def test_prefer_primary_returns(self):
        c = FailoverController(members(), FailoverPolicy(
            failure_threshold=1, recovery_threshold=1,
            preemption="PREFER_PRIMARY", prefer_primary_recovery_s=0,
            cooldown_s=0))
        c.on_probe("m0", False)
        c.decide()
        c.on_probe("m0", True)
        r = c.decide()
        assert r is not None and r.to == "m0"

    def test_best_score_guards_margin(self):
        policy = FailoverPolicy(failure_threshold=1, recovery_threshold=1,
                                preemption="BEST_SCORE", hysteresis_margin=5.0,
                                cooldown_s=0, mode="SCORE_PRIORITY")
        c = FailoverController(members(), policy)
        c.set_score("m0", 90)
        c.set_score("m1", 92)                        # margin 2 < 5 → no switch
        c.on_probe("m0", True)
        c.on_probe("m1", True)
        assert c.decide() is None
        c.set_score("m1", 96)                        # margin 6 ≥ 5 → guarded switch
        r = c.decide()
        assert r is not None and r.to == "m1" and "score margin" in r.reason

    def test_score_priority_mode_picks_best_eligible(self):
        c = FailoverController(members(), FailoverPolicy(
            mode="SCORE_PRIORITY", failure_threshold=1, cooldown_s=0,
            preemption="BEST_SCORE", recovery_threshold=1, hysteresis_margin=5.0))
        c.set_score("m0", 90)
        c.set_score("m2", 99)
        c.on_probe("m0", True)
        c.on_probe("m2", True)
        r = c.decide()                               # guarded reselection to m2
        assert r is not None and r.to == "m2"        # score beats priority


class TestGuards:
    def test_manual_pin_holds_against_score_and_failure(self):
        c = FailoverController(members(), FailoverPolicy(
            mode="SCORE_PRIORITY", failure_threshold=1, cooldown_s=0,
            preemption="BEST_SCORE", recovery_threshold=1))
        c.pin("m1")
        c.decide()                                   # applies the pin: -> m1
        assert c.active == "m1"
        c.set_score("m2", 99)
        c.on_probe("m2", True)
        c.on_probe("m1", True)
        assert c.decide() is None                    # scores cannot override the pin

    def test_maintenance_moves_off_active(self):
        c = FailoverController(members())
        c.set_maintenance("m0", True)
        r = c.decide()
        assert r is not None and r.to == "m1" and "maintenance" in r.reason

    def test_cooldown_suppresses_preemption_until_expired(self):
        c = FailoverController(members(), FailoverPolicy(
            failure_threshold=1, recovery_threshold=1, cooldown_s=100.0,
            preemption="PREFER_PRIMARY", prefer_primary_recovery_s=0))
        c.on_probe("m0", False)
        c.decide()                                   # -> m1 at t=0
        c.on_probe("m0", True)                       # primary recovered
        assert c.decide() is None                    # cooldown suppresses return
        c.advance(101.0)
        r = c.decide()
        assert r is not None and r.to == "m0"        # cooldown expired

    def test_emergency_overrides_cooldown(self):
        c = FailoverController(members(), FailoverPolicy(
            failure_threshold=1, cooldown_s=100.0))
        c.on_probe("m0", False)
        c.decide()                                   # -> m1 at t=0
        c.on_probe("m1", False)                      # active truly dead
        r = c.decide()                               # EMERGENCY overrides cooldown
        assert r is not None and r.actor == "EMERGENCY" and r.to == "m2"

    def test_flap_lock_engages_and_resets(self):
        policy = FailoverPolicy(failure_threshold=1, cooldown_s=0,
                                max_switches_per_window=2, flap_window_s=300,
                                flap_lock_s=120)
        c = FailoverController(members(4), policy)
        for _ in range(3):                           # 3rd switch exceeds window max
            c.on_probe(c.active, False)
            c.decide()
        assert c._flap_blocked()                     # lock engaged
        c.reset_flap()
        assert not c._flap_blocked()

    def test_emergency_overrides_flap_lock(self):
        policy = FailoverPolicy(failure_threshold=1, cooldown_s=0,
                                max_switches_per_window=1, flap_lock_s=999)
        c = FailoverController(members(4), policy)
        c.on_probe("m0", False)
        c.decide()
        c.on_probe("m1", False)
        c.decide()                                   # 2nd switch trips the lock
        assert c._flap_blocked()
        c.on_probe("m2", False)                      # active truly dead
        r = c.decide()
        assert r is not None and r.actor == "EMERGENCY" and r.to == "m3"


class TestReceipts:
    def test_every_switch_recorded_with_context(self):
        c = FailoverController(members(), FailoverPolicy(failure_threshold=1))
        c.on_probe("m0", False)
        c.decide()
        assert len(c.switch_receipts) == 1
        r = c.switch_receipts[0]
        assert (r.frm, r.to) == ("m0", "m1")
        assert r.threshold_state["failure_threshold"] == 1
        assert r.cooldown_state["cooldown_s"] == 30.0
        assert r.ts >= 0


class TestComponentRepair:
    def test_repair_failed_component_only(self):
        d = decide_repair(["frp"], ["wireguard"])
        assert d.action == "REPAIR_COMPONENT" and d.component == "frp"
        assert "wireguard" in d.reason

    def test_repair_budget_exhausted_switches_chain(self):
        d = decide_repair(["frp"], ["wireguard"], repair_attempts=2)
        assert d.action == "SWITCH_CHAIN"

    def test_underlay_failure_abandons_chain(self):
        d = decide_repair(["wireguard", "frp"], [])
        assert d.action == "SWITCH_CHAIN" and "underlay" in d.reason

    def test_propagation_marks_all_riders(self):
        comps = {"wg": None, "openvpn": "wg", "gre": "openvpn", "side-frp": "wg"}
        assert propagate_underlay_failure(comps, "wg") == \
            ["gre", "openvpn", "side-frp"]
        assert propagate_underlay_failure(comps, "openvpn") == ["gre"]


class TestDiversity:
    def test_shared_underlay_warning_and_recommendation(self):
        from orchestrator.benchmarking.chains import ChainSpec, CompSpec

        def spec(under, over, name):
            return ChainSpec(name, [CompSpec("u", under),
                                    CompSpec("o", over, parent_id="u")])

        primary = spec("wireguard", "frp", "primary")
        backup_same = spec("wireguard", "xray", "backup-same-underlay")
        backup_diff = spec("openvpn", "gost", "backup-diverse")
        warnings = diversity_warnings(primary, [backup_same, backup_diff])
        assert len(warnings) == 1
        assert warnings[0]["warning"] == "BACKUP_SHARES_UNDERLAY_WITH_PRIMARY"
        rec = diversity_recommendation(primary, [backup_same, backup_diff])
        assert "backup-diverse" in rec and "diversity" in rec
