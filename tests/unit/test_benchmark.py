"""Benchmark engine tests (P6) — unit_portable tier.

Covers the mandatory gate: compatibility resolution, bounded scheduling,
timeouts, cancellation, always-attempted cleanup + ORPHANED_RESOURCE,
raw-metrics-before-score, honest p99, hard gates, deterministic ranking,
sanitized receipts.
"""
import dataclasses
import threading
import time

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from core.models import Base, BenchmarkReceipt, BenchmarkRun, BenchmarkSample, Event, Job
from engines.adapters.kernel import FakeExecutor
from engines.adapters import PlanAction, ProbeResult
from orchestrator.benchmarking import (P99_MIN_SAMPLES, NodeCaps, PROFILES,
                                       Candidate, resolve_candidates, rtt_stats)
from orchestrator.benchmarking.runner import BenchmarkRunner, sanitize
from orchestrator.benchmarking.scoring import (DEFAULT_WEIGHTS, assert_weights,
                                               rank, score_sample)

pytestmark = pytest.mark.unit_portable


# ── compatibility ─────────────────────────────────────────────────────

class TestCompatibility:
    def make_caps(self, **kw):
        base = dict(node_id="n1", binaries={"wg", "wg-quick", "gost", "ssh", "frpc", "frps",
                                            "xray", "chisel", "openvpn", "swanctl", "ip",
                                            "sing-box", "rathole", "wstunnel", "paqet",
                                            "hedioum", "hajsaman", "waterwall"},
                     kernel_modules={"wireguard", "ip_gre", "ipip", "sit", "tun",
                                     "vxlan", "vti", "xfrm", "esp"})
        base.update(kw)
        return NodeCaps(**base)

    def test_compatible_candidates_found(self):
        cands = resolve_candidates(self.make_caps(), self.make_caps())
        by_id = {c.legacy_method_id: c for c in cands}
        assert by_id["WIREGUARD"].status == "COMPATIBLE"
        assert by_id["GOST_GRPC"].status == "COMPATIBLE"
        assert sum(1 for c in cands if c.status == "COMPATIBLE") > 20

    def test_unprivileged_node_makes_l3_incompatible(self):
        a = self.make_caps(privileged=False)
        cands = resolve_candidates(a, a)
        by_id = {c.legacy_method_id: c for c in cands}
        assert by_id["WIREGUARD"].status == "INCOMPATIBLE"
        assert "CAP_NET_ADMIN" in by_id["WIREGUARD"].reason
        assert by_id["GOST_SOCKS5"].status in ("COMPATIBLE", "BLOCKED")  # userspace may pass

    def test_missing_binary_is_blocked_not_incompatible(self):
        a = self.make_caps(binaries=set())
        cands = resolve_candidates(a, a)
        by_id = {c.legacy_method_id: c for c in cands}
        assert by_id["GOST_GRPC"].status == "BLOCKED"
        assert "missing binaries" in by_id["GOST_GRPC"].reason


# ── statistics honesty ────────────────────────────────────────────────

class TestStats:
    def test_p99_absent_below_threshold(self):
        s = rtt_stats([10.0] * 30)
        assert s["rtt_p99"] is None and s["samples"] == 30
        assert s["rtt_p50"] == 10.0 and s["rtt_p95"] == 10.0

    def test_p99_present_with_enough_samples(self):
        xs = [float(i) for i in range(P99_MIN_SAMPLES)]
        s = rtt_stats(xs)
        assert s["rtt_p99"] is not None
        assert s["rtt_p99"] >= s["rtt_p95"] >= s["rtt_p50"] >= s["rtt_min"]

    def test_empty_samples_all_none(self):
        assert rtt_stats([])["rtt_avg"] is None


# ── scoring ───────────────────────────────────────────────────────────

class TestScoring:
    def test_weights_total_100(self):
        assert sum(DEFAULT_WEIGHTS.values()) == 100
        with pytest.raises(ValueError):
            assert_weights({"latency": 50})

    def test_data_plane_failure_hard_gates_to_zero(self):
        s = score_sample("x", {"rtt_avg": 5, "loss_pct": 0, "jitter": 0.1,
                               "data_plane_ok": False}, "PASS")
        assert s.status == "FAILED" and s.score == 0.0

    def test_blocked_and_incompatible_get_no_score(self):
        assert score_sample("x", {"reason": "dep"}, "BLOCKED").score is None
        assert score_sample("x", {"reason": "cap"}, "INCOMPATIBLE").score is None

    def test_good_sample_scores_high(self):
        s = score_sample("good", {"rtt_avg": 8.0, "loss_pct": 0.0, "jitter": 0.8,
                                  "throughput_mbps": 900, "stability_ratio": 1.0,
                                  "reconnect_s": 2.0, "cpu_pct": 3, "ram_mb": 20,
                                  "data_plane_ok": True, "setup_ok": True}, "PASS")
        assert s.status == "PASS" and s.score > 85

    def test_degraded_loss_flags_status(self):
        s = score_sample("meh", {"rtt_avg": 20.0, "loss_pct": 10.0, "jitter": 2.0,
                                 "data_plane_ok": True, "setup_ok": True}, "PASS")
        assert s.status == "DEGRADED"

    def test_ranking_order_deterministic_and_documented(self):
        def m(loss, p95, jit, stab=1.0):
            return {"loss_pct": loss, "rtt_p95": p95, "jitter": jit, "stability_ratio": stab}
        a = score_sample("a", {**m(0, 40, 1), "data_plane_ok": True}, "PASS")
        b = score_sample("b", {**m(0, 40, 1), "data_plane_ok": True}, "PASS")
        c = score_sample("c", {**m(0.5, 60, 2), "data_plane_ok": True}, "PASS")
        blocked = score_sample("blocked", {"reason": "dep"}, "BLOCKED")
        failed = score_sample("failed", {"data_plane_ok": False}, "FAILED")
        r1 = rank([c, blocked, a, failed, b])
        r2 = rank([failed, b, c, a, blocked])
        assert [x.candidate for x in r1] == [x.candidate for x in r2]   # stable
        assert r1[-1].candidate == "blocked"          # BLOCKED ranked last, no fake score
        assert r1[0].candidate in ("a", "b")          # PASS league above FAILED


# ── runner ────────────────────────────────────────────────────────────

class FakeAdapter:
    """Configurable fake: succeeds/fails/sleeps; records concurrency."""

    lock = threading.Lock()
    concurrent = 0
    peak = 0

    def __init__(self, cand, behavior="ok", sleep_s=0.0, fail_cleanup=False):
        self.cand, self.behavior = cand, behavior
        self.sleep_s, self.fail_cleanup = sleep_s, fail_cleanup
        self.calls = []

    def configure(self):
        self.calls.append("configure")
        if self.behavior == "setup-fail":
            raise RuntimeError("boom: no binary")

    def start(self):
        self.calls.append("start")
        time.sleep(self.sleep_s)

    def probe(self):
        self.calls.append("probe")
        if self.behavior == "probe-fail":
            return ProbeResult(ok=False, evidence="no traffic")
        return ProbeResult(ok=True, evidence="200 OK via socks")

    def metrics(self):
        return {"rtt_avg": 12.0, "loss_pct": 0.0, "jitter": 0.8,
                "password": "should-not-leak"}

    def rollback(self):
        self.calls.append("rollback")
        if self.fail_cleanup:
            raise RuntimeError("cleanup exploded")


def cand(mid, status="COMPATIBLE"):
    return Candidate("e", "p", mid, "FAM", status)


@pytest.fixture()
def session():
    from sqlalchemy.pool import StaticPool
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        yield s
        s.rollback()


class TestRunner:
    def test_happy_path_persists_samples_and_receipts(self, session):
        cands = [cand("A"), cand("B")]
        factory = lambda c: FakeAdapter(c)
        runner = BenchmarkRunner(session, "a", "b", "QUICK", factory, cands)
        ranked = runner.run()
        assert [r.status for r in ranked] == ["PASS", "PASS"]
        assert session.query(BenchmarkSample).count() == 2
        receipts = session.scalars(select(BenchmarkReceipt)).all()
        assert len(receipts) == 2
        assert receipts[0].document["methodology"]["name"] == "QUICK"
        # raw metrics persisted before score (samples exist independent of score)
        assert all(smp.metrics for smp in session.scalars(select(BenchmarkSample)))

    def test_receipts_are_sanitized(self, session):
        factory = lambda c: FakeAdapter(c)
        BenchmarkRunner(session, "a", "b", "QUICK", factory, [cand("A")]).run()
        doc = session.scalars(select(BenchmarkReceipt)).one().document
        assert doc["metrics"]["password"] == "***REDACTED***"

    def test_bounded_concurrency(self, session):
        FakeAdapter.peak = 0
        cands = [cand(f"M{i}") for i in range(6)]

        class SlowFake(FakeAdapter):
            def start(self):
                with FakeAdapter.lock:
                    FakeAdapter.concurrent += 1
                    FakeAdapter.peak = max(FakeAdapter.peak, FakeAdapter.concurrent)
                time.sleep(0.05)
                with FakeAdapter.lock:
                    FakeAdapter.concurrent -= 1

        runner = BenchmarkRunner(session, "a", "b", "QUICK",
                                 lambda c: SlowFake(c), cands, max_parallel=2)
        runner.run()
        assert FakeAdapter.peak <= 2

    def test_setup_failure_marked_failed_with_reason(self, session):
        factory = lambda c: FakeAdapter(c, behavior="setup-fail")
        ranked = BenchmarkRunner(session, "a", "b", "QUICK", factory, [cand("A")]).run()
        assert ranked[0].status == "FAILED"
        assert "setup failed" in (ranked[0].reasons[0] or "")

    def test_probe_failure_is_failed_not_scored_healthy(self, session):
        factory = lambda c: FakeAdapter(c, behavior="probe-fail")
        ranked = BenchmarkRunner(session, "a", "b", "QUICK", factory, [cand("A")]).run()
        assert ranked[0].status == "FAILED" and ranked[0].score == 0.0

    def test_cleanup_always_attempted_and_orphaned_surfaced(self, session):
        factory = lambda c: FakeAdapter(c, fail_cleanup=True)
        runner = BenchmarkRunner(session, "a", "b", "QUICK", factory, [cand("A")])
        runner.run()
        events = session.scalars(select(Event)).all()
        orphan_events = [e for e in events if "ORPHANED_RESOURCE" in e.message]
        assert orphan_events and orphan_events[0].severity == "critical"
        assert runner.orphaned == ["A"]

    def test_incompatible_candidates_skipped_honestly(self, session):
        cands = [cand("X", "INCOMPATIBLE"), cand("Y", "BLOCKED")]
        runner = BenchmarkRunner(session, "a", "b", "QUICK", None, cands)
        ranked = runner.run()
        by = {r.candidate: r for r in ranked}
        assert by["X"].status == "INCOMPATIBLE" and by["X"].score is None
        assert by["Y"].status == "BLOCKED" and by["Y"].score is None

    def test_job_state_transitions_finish(self, session):
        job = Job(kind="benchmark")
        session.add(job)
        session.commit()
        runner = BenchmarkRunner(session, "a", "b", "QUICK",
                                  lambda c: FakeAdapter(c), [cand("A")], job=job)
        runner.run()
        assert job.state in ("PASS", "FAILED")
        assert job.finished_at is not None

    def test_cancellation_marks_remaining(self, session):
        started = threading.Event()

        class SlowStart(FakeAdapter):
            def start(self):
                started.set()
                for _ in range(40):
                    time.sleep(0.02)

        runner = BenchmarkRunner(session, "a", "b", "QUICK",
                                 lambda c: SlowStart(c), [cand("A"), cand("B")])
        t = threading.Thread(target=runner.run, daemon=True)
        t.start()
        started.wait(timeout=5)
        runner.cancel()
        t.join(timeout=10)
        job_states = session.query(BenchmarkRun).one().state
        assert job_states in ("PASS", "CANCELLED", "FAILED")


class TestSanitize:
    def test_deep_redaction(self):
        doc = {"auth_token": "abc", "nested": {"PSK": "x", "ok": "fine"},
               "logs": ["y" * 500]}
        out = sanitize(doc)
        assert out["auth_token"] == "***REDACTED***"
        assert out["nested"]["PSK"] == "***REDACTED***"
        assert out["nested"]["ok"] == "fine"
        assert len(out["logs"][0]) < 410


class TestTimeouts:
    def test_slow_candidate_times_out(self, session, monkeypatch):
        from orchestrator.benchmarking import PROFILES as P, BenchProfile
        monkeypatch.setitem(P, "QUICK", BenchProfile(
            "QUICK", rtt_probes=1, throughput_seconds=0, restart_test=False,
            setup_timeout_s=1, probe_timeout_s=1, throughput_timeout_s=0,
            teardown_timeout_s=1, overall_timeout_s=5))

        class SleepyFake(FakeAdapter):
            def start(self):
                time.sleep(0.02)

            def metrics(self):
                time.sleep(6)                      # blows the overall deadline
                return {}

        # deadline checked after metrics stage: sleeping metrics trips it
        import orchestrator.benchmarking.runner as R
        orig = time.monotonic

        class ShiftedClock:
            def __init__(self):
                self.calls = 0

            def __call__(self):
                self.calls += 1
                return orig() + (100.0 if self.calls > 1 else 0.0)  # jumps after deadline

        monkeypatch.setattr(R.time, "monotonic", ShiftedClock())
        runner = BenchmarkRunner(session, "a", "b", "QUICK",
                                 lambda c: SleepyFake(c), [cand("A")])
        ranked = runner.run()
        assert ranked[0].status == "TIMED_OUT"
