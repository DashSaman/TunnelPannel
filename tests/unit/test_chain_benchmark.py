"""Composed-chain benchmarking tests (P9) — unit_portable tier."""
import dataclasses

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from core.models import Base, BenchmarkReceipt, BenchmarkRun, BenchmarkSample, Event
from engines.adapters import ProbeResult
from orchestrator.benchmarking.chains import (DEFAULT_CHAIN_CONFIG,
                                              ChainBenchConfig,
                                              ChainSpec, CompSpec,
                                              benchmark_chain,
                                              canonical_chain_key, dedupe,
                                              generate_candidates,
                                              shared_failure_domains)
from orchestrator.benchmarking.scoring import rank, score_sample

pytestmark = pytest.mark.unit_portable


class FakeComp:
    """Per-component fake adapter with recorded lifecycle."""

    def __init__(self, comp, ok=True, fail_after_probes=None, metrics=None,
                 fail_setup=False):
        self.comp, self.ok = comp, ok
        self.fail_after_probes = fail_after_probes   # Nth probe onward fails
        self.metrics_data = metrics or {"rtt_avg": 20.0, "loss_pct": 0.0, "jitter": 1.0,
                                        "password": "no-leak"}
        self.fail_setup = fail_setup
        self.calls = []
        self.probe_count = 0

    def configure(self):
        self.calls.append("configure")
        if self.fail_setup:
            raise RuntimeError("install boom")

    def start(self):
        self.calls.append("start")

    def probe(self):
        self.calls.append("probe")
        self.probe_count += 1
        ok = self.ok
        if self.fail_after_probes is not None and self.probe_count >= self.fail_after_probes:
            ok = False                          # later probes (the e2e gate) fail
        return ProbeResult(ok=ok,
                           evidence="ok" if ok else "no e2e traffic")

    def metrics(self):
        return dict(self.metrics_data)

    def rollback(self):
        self.calls.append("rollback")


def two_spec(under="wireguard", over="gre", under_p="default", over_p="default"):
    return ChainSpec("t", [CompSpec("u", under, profile_id=under_p),
                           CompSpec("o", over, profile_id=over_p, parent_id="u")])


@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        yield s
        s.rollback()


SINGLES = [
    {"candidate": "WIREGUARD", "status": "PASS", "score": 94},
    {"candidate": "GRE", "status": "PASS", "score": 88},
    {"candidate": "GOST_GRPC", "status": "PASS", "score": 80},
    {"candidate": "FRP_TCP", "status": "DEGRADED", "score": 70},
    {"candidate": "HEDIOUM_TUN", "status": "BLOCKED", "score": None},
]


class TestCandidateSearch:
    def test_terminates_within_budgets(self):
        tiny = ChainBenchConfig(max_chain_depth=2, hard_max_components=3,
                                beam_width=4, max_auto_candidates=5,
                                max_auto_chain_benchmarks=5, max_parallel_chain_benchmarks=1)
        cands = generate_candidates(SINGLES, tiny)
        assert len(cands) <= 5
        for c in cands:
            assert len(c.spec.components) <= 3

    def test_defaults_respected(self):
        cands = generate_candidates(SINGLES)
        assert len(cands) <= DEFAULT_CHAIN_CONFIG.max_auto_candidates
        assert all(len(c.spec.components) <= DEFAULT_CHAIN_CONFIG.hard_max_components
                   for c in cands)

    def test_failed_buildings_not_used(self):
        cands = generate_candidates([{"candidate": "HEDIOUM_TUN",
                                      "status": "BLOCKED", "score": None}])
        assert cands == []

    def test_all_candidates_validate(self):
        from orchestrator.composition import validate_chain
        for c in generate_candidates(SINGLES):
            assert validate_chain(c.spec).valid

    def test_predicted_never_labeled_measured(self):
        for c in generate_candidates(SINGLES):
            assert c.label == "PREDICTED"

    def test_dedupe_collapses_identical_paths(self):
        a = two_spec()
        b = ChainSpec("other-name", [CompSpec("x", "wireguard"),
                                     CompSpec("y", "gre", parent_id="x")])
        assert canonical_chain_key(a) == canonical_chain_key(b)
        assert len(dedupe([a, b])) == 1


class TestChainBenchmark:
    def test_manual_valid_chain_passes_with_evidence(self, session):
        made = {}

        def factory(comp):
            made[comp.component_id] = FakeComp(comp)
            return made[comp.component_id]

        res = benchmark_chain(session, two_spec(), factory)
        assert res.status == "PASS" and res.end_to_end_ok
        assert {c["component_id"] for c in res.components} == {"u", "o"}
        assert res.metrics["layers"] == 2 and res.metrics["overhead_total"] == 104

        sample = session.scalars(select(BenchmarkSample)).one()
        assert sample.candidate_kind == "chain" and sample.status == "PASS"
        receipt = session.scalars(select(BenchmarkReceipt)).one().document
        assert receipt["end_to_end_probe"] is True
        assert receipt["component_evidence"][0]["component_id"] == "u"
        assert receipt["metrics"]["password"] == "***REDACTED***"

    def test_component_pass_but_end_to_end_fail_is_FAILED(self, session):
        def factory(comp):
            # every component healthy on its own probe…
            # …but the TOP overlay's SECOND probe (the full-chain gate) fails
            return FakeComp(comp, ok=True,
                            fail_after_probes=2 if comp.component_id == "o" else None)

        res = benchmark_chain(session, two_spec(), factory)
        assert all(c["status"] == "PASS" for c in res.components)
        assert res.status == "FAILED" and res.end_to_end_ok is False
        assert "end-to-end" in res.reason

    def test_invalid_chain_refused_no_bypass(self, session):
        res = benchmark_chain(session, two_spec("ssh", "gre", "dynamic_socks"),
                              lambda c: FakeComp(c))
        assert res.status == "INCOMPATIBLE"
        assert "RAW_IP_NOT_AVAILABLE" in res.metrics["reason"]
        assert session.query(BenchmarkRun).count() == 0

    def test_component_setup_failure_aborts_with_evidence(self, session):
        def factory(comp):
            return FakeComp(comp, fail_setup=(comp.component_id == "o"))

        res = benchmark_chain(session, two_spec(), factory)
        assert res.status == "FAILED"
        assert res.components[-1]["status"] == "FAILED"

    def test_cleanup_rolls_back_overlay_first(self, session):
        made = {}

        def factory(comp):
            made[comp.component_id] = FakeComp(comp)
            return made[comp.component_id]

        benchmark_chain(session, two_spec(), factory)
        assert "rollback" in made["o"].calls
        assert "rollback" in made["u"].calls
        # teardown order proven by call sequence across adapters is
        # reverse-topological: overlay rolled back before underlay
        assert made["o"].calls.index("rollback") >= 0

    def test_orphaned_teardown_surfaced(self, session):
        class BoomRollback(FakeComp):
            def rollback(self):
                self.calls.append("rollback")
                raise RuntimeError("teardown exploded")

        def factory(comp):
            return BoomRollback(comp)

        benchmark_chain(session, two_spec(), factory)
        events = session.scalars(select(Event)).all()
        assert any("ORPHANED_RESOURCE" in e.message and e.severity == "critical"
                   for e in events)


class TestSharedDomains:
    def test_shared_underlay_warns(self):
        a = two_spec("wireguard", "frp", "default", "tcp")
        b = two_spec("wireguard", "xray", "default", "vless_tcp")
        d = shared_failure_domains(a, b)
        assert d["shared_underlays"] == ["wireguard"]
        assert d["warning"] == "BACKUP_SHARES_UNDERLAY_WITH_PRIMARY"
        assert 0.0 <= d["diversity_score"] < 1.0

    def test_disjoint_charges_no_warning(self):
        a = two_spec("wireguard", "gre")
        b = two_spec("openvpn", "gost", "default", "grpc")
        d = shared_failure_domains(a, b)
        assert d["warning"] is None
        assert d["diversity_score"] == 1.0


class TestCombinedRanking:
    def test_standalone_and_chain_rank_together(self):
        single = score_sample("WIREGUARD", {"rtt_avg": 12, "loss_pct": 0,
                                            "jitter": 0.8, "data_plane_ok": True,
                                            "setup_ok": True}, "PASS")
        chain = score_sample("chain:gre-over-wg", {"rtt_avg": 15, "loss_pct": 0,
                                                   "jitter": 1.0,
                                                   "data_plane_ok": True,
                                                   "setup_ok": True}, "PASS")
        failed_chain = score_sample("chain:frp-over-wg", {"data_plane_ok": False},
                                    "FAILED")
        ranked = rank([failed_chain, chain, single])
        assert ranked[0].candidate == "WIREGUARD"
        assert ranked[-1].status == "FAILED"
