"""Observability + alerting + bot tests (P12 §25) — unit_portable tier."""
import datetime as dt

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from apps.bot.core import BotCore, NotAuthorized, ConfirmationRequired
from core.models import Base, HealthSample
from orchestrator.alerting import (CRITICAL, WARNING, AlertEngine,
                                   evaluate_health,
                                   failover_alerts)
from orchestrator.observability import (apply_retention, prometheus_export,
                                         record_sample, rollup,
                                         stability_profile)

pytestmark = pytest.mark.unit_portable


class FakeApi:
    def __init__(self, data):
        self.data = data

    def get(self, path):
        return self.data.get(path, {})

    def post(self, path, body):
        return {"ok": True, "path": path}


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        yield s
        s.rollback()


# ── observability ─────────────────────────────────────────────────────

class TestHealthSampling:
    def test_metric_persistence(self, session):
        record_sample(session, "WIREGUARD", True, rtt_ms=12.5, jitter_ms=0.8,
                      loss_pct=0.0, state="UP")
        record_sample(session, "WIREGUARD", False, state="DOWN")
        rows = session.scalars(select(HealthSample)).all()
        assert len(rows) == 2 and rows[0].candidate == "WIREGUARD"

    def test_rollup_aggregates_buckets(self, session):
        base = dt.datetime(2026, 10, 3, 12, 0, 0, tzinfo=dt.timezone.utc)
        for i in range(6):
            ts = base + dt.timedelta(seconds=i * 50)   # stays inside one 300s bucket
            s = record_sample(session, "X", True, rtt_ms=10.0 + i)
            s.ts = ts
            session.commit()
        for i in range(4):
            s = record_sample(session, "X", i % 2 == 0, rtt_ms=50.0)
            s.ts = base + dt.timedelta(seconds=600 + i * 60)
            session.commit()
        samples = session.scalars(select(HealthSample)).all()
        buckets = rollup(samples, bucket_s=300)
        assert len(buckets) == 2
        assert buckets[0].n == 6 and buckets[0].availability == 1.0
        assert buckets[1].n == 4 and buckets[1].availability == 0.5
        assert buckets[0].rtt_p95 >= buckets[0].rtt_p50

    def test_retention_splits_raw_samples(self, session):
        now = dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc)
        old = record_sample(session, "X", True)
        old.ts = now - dt.timedelta(hours=10)
        new = record_sample(session, "X", True)
        new.ts = now - dt.timedelta(minutes=5)
        session.commit()
        keep, drop = apply_retention([old, new], now.timestamp(),
                                     __import__("orchestrator.observability",
                                                fromlist=["RetentionPolicy"])
                                     .RetentionPolicy(hi_res_keep_s=3600))
        assert [s.id for s in keep] == [new.id]
        assert [s.id for s in drop] == [old.id]

    def test_stability_distinguishes_fast_unstable(self, session):
        def mk(ok, rtt):
            s = HealthSample(candidate="c", ok=ok, rtt_ms=rtt)
            return s
        fast_unstable = [mk(i % 3 != 0, 20.0) for i in range(30)]
        p = stability_profile(fast_unstable)
        assert p.classification == "FAST_BUT_UNSTABLE"
        slower_stable = [mk(True, 90.0) for _ in range(30)]
        p2 = stability_profile(slower_stable)
        assert p2.classification == "SLOWER_BUT_STABLE"

    def test_prometheus_export_optional(self):
        text = prometheus_export({"rtt_avg": 12.5, "loss pct": 0.1})
        assert "# TYPE tunnelpannel_rtt_avg gauge" in text
        assert "tunnelpannel_loss_pct 0.1" in text


# ── alerting ──────────────────────────────────────────────────────────

class TestAlertRules:
    def test_node_down_critical(self):
        out = evaluate_health("n1", "node", [{"ok": False} for _ in range(4)])
        assert ("NODE_DOWN", CRITICAL) in out

    def test_high_loss_and_jitter(self):
        out = evaluate_health("t1", "tunnel", [
            {"ok": True, "loss_pct": 7.0, "jitter_ms": 60.0, "rtt_ms": 100.0}])
        kinds = [k for k, _s in out]
        assert "HIGH_LOSS" in kinds and "HIGH_JITTER" in kinds

    def test_degraded_streak(self):
        out = evaluate_health("t1", "tunnel", [
            {"ok": True}, {"ok": False}, {"ok": False}, {"ok": False}])
        assert ("DEGRADED", WARNING) in out

    def test_healthy_no_alerts(self):
        assert evaluate_health("t1", "tunnel", [
            {"ok": True, "loss_pct": 0.0, "jitter_ms": 1.0, "rtt_ms": 20.0}]) == []

    def test_frequent_failover(self):
        now = 1000.0
        switches = [now - 100 * i for i in range(6)]
        assert failover_alerts(switches, now) == [("FREQUENT_FAILOVER", WARNING)]


class TestAlertEngine:
    def test_dedupe_single_incident_no_storm(self):
        e = AlertEngine(notification_cooldown_s=900.0)
        notes = []
        for i in range(100):                          # same failure 100 times
            notes.extend(e.evaluate("node:n1", "NODE_DOWN", CRITICAL,
                                    ts=float(i)))
        assert len(notes) == 1                         # ONE notification
        assert e.active()[0].occurrences == 100

    def test_cooldown_resends_after_window(self):
        e = AlertEngine(notification_cooldown_s=60.0)
        n1 = e.evaluate("k", "HIGH_LOSS", WARNING, ts=0.0)
        n2 = e.evaluate("k", "HIGH_LOSS", WARNING, ts=30.0)
        n3 = e.evaluate("k", "HIGH_LOSS", WARNING, ts=120.0)
        assert len(n1) == 1 and n2 == [] and len(n3) == 1

    def test_resolution_with_duration(self):
        e = AlertEngine()
        e.evaluate("k", "TUNNEL_DOWN", CRITICAL, ts=0.0, evidence="probe fail")
        r = e.resolve("k", ts=300.0)
        assert r.is_resolution and "300s" in r.text
        assert e.active() == []
        assert e.resolve("k", ts=400.0) is None       # no double resolution

    def test_severity_escalation_updates_incident(self):
        e = AlertEngine()
        e.evaluate("k", "DEGRADED", WARNING, ts=0.0)
        e.evaluate("k", "DEGRADED", CRITICAL, ts=10.0)
        assert e.active()[0].severity == CRITICAL


# ── bot ───────────────────────────────────────────────────────────────

class TestBot:
    def make(self):
        api = FakeApi({
            "/api/status": {"mode": "auto", "active": "wg0", "up": 12, "total": 14,
                            "active_alerts": 1},
            "/api/nodes": [{"name": "gw-ir", "host": "198.51.100.1"}],
            "/failover-groups": [{"name": "edge", "mode": "MANUAL_PRIORITY",
                                  "active": "m0"}],
            "/api/alerts/active": [{"severity": "CRITICAL", "kind": "NODE_DOWN",
                                    "key": "node:n1", "occurrences": 4}],
            "/api/topology": {"edges": [{"from_node": "iran", "to_node": "turkey",
                                         "route": "WIREGUARD"}]},
            "/benchmarks": [{"job_id": "abcd1234", "state": "PASS",
                             "compatible": 31}],
        })
        return BotCore(api, allowed_user_ids={42, 99})

    def test_unauthorized_user_rejected(self):
        core = self.make()
        with pytest.raises(NotAuthorized):
            core.handle(12345, "/status")

    def test_status_formatting(self):
        out = self.make().handle(42, "/status")
        assert "active: wg0" in out and "12/14" in out

    def test_unknown_command_lists_commands(self):
        out = self.make().handle(42, "/frobnicate")
        assert "/status" in out

    def test_alerts_format(self):
        out = self.make().handle(42, "/alerts")
        assert "NODE_DOWN" in out and "x4" in out

    def test_dangerous_requires_confirmation(self):
        core = self.make()
        first = core.handle(42, "/maintenance gw-ir on")
        assert "/confirm" in first
        token = first.split()[-1]
        result = core.handle(42, f"/confirm {token}")
        assert "maintenance" in result

    def test_confirm_without_pending_fails(self):
        with pytest.raises(ConfirmationRequired):
            self.make().handle(42, "/confirm deadbeef")

    def test_secret_redaction_in_messages(self):
        core = self.make()
        text = core.format_notification("node password=hunter42 rejected ghp_" + "A" * 30)
        assert "hunter42" not in text and "ghp_" not in text

    def test_switch_notification_format(self):
        core = self.make()
        out = core.format_switch({"frm": "m0", "to": "m1", "actor": "AUTO",
                                  "reason": "3 consecutive bad probes"})
        assert "m0 → m1" in out and "AUTO" in out
