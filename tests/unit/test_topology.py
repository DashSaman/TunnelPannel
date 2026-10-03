"""Topology + multi-hop tests (P11 §13) — unit_portable tier."""
import time

import pytest

from orchestrator.composition import ChainSpec, CompSpec
from orchestrator.failover import FailoverController, FailoverPolicy, MemberRuntime
from orchestrator.topology import (PathSearchConfig, Topology, TopologyEdge,
                                   TopologyPath, candidate_paths,
                                   derive_path_metrics, hop_failure_effect,
                                   path_loops, path_member_candidate,
                                   path_plan, path_score, route_dependency_cycle,
                                   shared_path_domains, validate_path,
                                   verify_path_end_to_end)

pytestmark = pytest.mark.unit_portable


def ir_tr_de_fg():
    """Iran → Turkey → Germany (+ Finland branch) with measured hops."""
    return Topology("eurasia", edges=[
        TopologyEdge("ir-tr", "iran", "turkey", "WIREGUARD",
                     rtt_ms=40.0, loss_pct=0.5, throughput_mbps=500.0,
                     availability=0.999, effective_mtu=1420,
                     verification="REAL_PAIR_VERIFIED"),
        TopologyEdge("tr-de", "turkey", "germany", "GRE",
                     rtt_ms=25.0, loss_pct=0.2, throughput_mbps=800.0,
                     availability=0.995, effective_mtu=1476,
                     verification="REAL_PAIR_VERIFIED"),
        TopologyEdge("ir-fi", "iran", "finland", "GOST_GRPC",
                     rtt_ms=55.0, loss_pct=1.0, throughput_mbps=300.0,
                     availability=0.99, effective_mtu=1500,
                     verification="LAB_VERIFIED"),
        TopologyEdge("fi-de", "finland", "germany", "FRP_TCP",
                     rtt_ms=30.0, loss_pct=0.4, throughput_mbps=900.0,
                     availability=0.997, effective_mtu=1500,
                     verification="REAL_PAIR_VERIFIED"),
    ])


class TestGraphRules:
    def test_node_cycle_rejected(self):
        topo = Topology("t", [
            TopologyEdge("ab", "a", "b", "WIREGUARD"),
            TopologyEdge("bc", "b", "c", "GRE"),
            TopologyEdge("ca", "c", "a", "VXLAN"),
        ])
        ok, problems = validate_path(topo, ["ab", "bc", "ca"])
        assert not ok and any(p.startswith("NODE_CYCLE") for p in problems)
        assert path_loops(topo, ["ab", "bc", "ca"]) == "a"

    def test_route_dependency_cycle_rejected(self):
        topo = Topology("t", [TopologyEdge("ab", "a", "b", "WIREGUARD"),
                              TopologyEdge("bc", "b", "c", "GRE"),
                              TopologyEdge("cd", "c", "d", "GRE")])  # GRE reused
        assert route_dependency_cycle(topo, ["ab", "bc", "cd"])
        ok, problems = validate_path(topo, ["ab", "bc", "cd"])
        assert any(p.startswith("ROUTE_CYCLE") for p in problems)

    def test_discontinuity_rejected(self):
        topo = ir_tr_de_fg()
        ok, problems = validate_path(topo, ["ir-tr", "fi-de"])   # turkey≠finland
        assert not ok and any(p.startswith("DISCONTINUOUS") for p in problems)

    def test_valid_2hop_and_3_hop(self):
        topo = ir_tr_de_fg()
        assert validate_path(topo, ["ir-tr", "tr-de"])[0]
        topo3 = Topology("t3", [
            TopologyEdge("ab", "a", "b", "WIREGUARD"),
            TopologyEdge("bc", "b", "c", "GRE"),
            TopologyEdge("cd", "c", "d", "VXLAN"),
        ])
        assert validate_path(topo3, ["ab", "bc", "cd"])[0]

    def test_chain_hop_validated_by_p8(self):
        bad_chain = ChainSpec("bad", [CompSpec("u", "ssh", profile_id="dynamic_socks"),
                                      CompSpec("o", "gre", parent_id="u")])
        topo = Topology("t", [TopologyEdge("ab", "a", "b", "chain:bad",
                                           route_kind="chain", chain_spec=bad_chain)])
        ok, problems = validate_path(topo, ["ab"])
        assert not ok and any("RAW_IP_NOT_AVAILABLE" in p for p in problems)


class TestPathMetrics:
    def test_latency_is_sum(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        assert m.latency_ms == pytest.approx(65.0)

    def test_combined_loss_probability(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        expected = 100.0 * (1 - (1 - 0.005) * (1 - 0.002))
        assert m.loss_pct == pytest.approx(expected, rel=1e-6)

    def test_bottleneck_throughput(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        assert m.throughput_mbps == 500.0                      # min, not avg

    def test_weakest_hop_availability(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        assert m.availability == pytest.approx(0.995)

    def test_effective_mtu_is_minimum(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        assert m.effective_mtu == 1420

    def test_measured_e2e_overrides_derived(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        m.e2e_latency_ms = 70.0
        m.e2e_loss_pct = 0.9
        s = m.summary()
        assert s["latency_ms"] == 70.0 and s["loss_pct"] == 0.9
        assert s["source"] == "measured"

    def test_path_score_is_own_not_average(self):
        m = derive_path_metrics(ir_tr_de_fg(), ["ir-tr", "tr-de"])
        score = path_score(m)
        assert score is not None and 0 <= score <= 100


class TestEndToEndGate:
    def test_healthy_hops_but_e2e_fail_not_verified(self):
        topo = ir_tr_de_fg()
        path = TopologyPath("p1", ["ir-tr", "tr-de"])
        ok, why = verify_path_end_to_end(topo, path,
                                         {"ir-tr": True, "tr-de": True},
                                         e2e_probe=False)
        assert not ok and path.state == "PATH_FAILED"
        assert "end-to-end" in why

    def test_all_pass_verifies(self):
        topo = ir_tr_de_fg()
        path = TopologyPath("p1", ["ir-tr", "tr-de"])
        ok, _ = verify_path_end_to_end(topo, path,
                                       {"ir-tr": True, "tr-de": True}, True)
        assert ok and path.state == "VERIFIED"

    def test_hop_failure_distinguished_from_path(self):
        topo = ir_tr_de_fg()
        path = TopologyPath("p1", ["ir-tr", "tr-de"])
        ok, why = verify_path_end_to_end(topo, path,
                                         {"ir-tr": True, "tr-de": False}, True)
        assert not ok and path.state == "HOP_FAILED"
        effect = hop_failure_effect(topo, path, "tr-de")
        assert effect["healthy_hops_to_preserve"] == ["ir-tr"]
        assert effect["whole_path_failed"]


class TestBoundedSearch:
    def test_terminates_and_finds_both_routes(self):
        topo = ir_tr_de_fg()
        paths = candidate_paths(topo, "iran", "germany",
                                PathSearchConfig(max_hops=3))
        ids = [tuple(p) for p in paths]
        assert ("ir-tr", "tr-de") in ids
        assert ("ir-fi", "fi-de") in ids
        assert all(len(p) <= 3 for p in paths)

    def test_budget_respected(self):
        topo = ir_tr_de_fg()
        tiny = PathSearchConfig(max_hops=2, max_candidate_paths=1,
                                beam_width=2, time_budget_s=10.0)
        assert len(candidate_paths(topo, "iran", "germany", tiny)) <= 1

    def test_time_budget_terminates(self):
        # dense graph, tiny budget — must return quickly, not hang
        edges = [TopologyEdge(f"e{i}", f"n{i}", f"n{(i + 1) % 12}", "WIREGUARD")
                 for i in range(12)]
        edges += [TopologyEdge(f"x{i}", f"n{i}", f"n{(i + 5) % 12}", "GRE")
                  for i in range(12)]
        topo = Topology("dense", edges)
        t0 = time.monotonic()
        candidate_paths(topo, "n0", "n6",
                        PathSearchConfig(max_hops=3, time_budget_s=0.05))
        assert time.monotonic() - t0 < 3.0


class TestSharedDomains:
    def test_shared_relay_detected(self):
        topo = ir_tr_de_fg()
        a = TopologyPath("via-tr", ["ir-tr", "tr-de"])
        b = TopologyPath("via-fi", ["ir-fi", "fi-de"])
        shared = shared_path_domains({"via-tr": a, "via-fi": b}, topo)
        d = shared["via-fi|via-tr"]
        assert "iran" in d["shared_nodes"]                  # common endpoint
        assert "turkey" not in d["shared_nodes"]            # different relays
        assert d["diversity_score"] > 0


class TestFailoverIntegration:
    def test_paths_as_failover_members(self):
        a = TopologyPath("via-tr", ["ir-tr", "tr-de"])
        b = TopologyPath("via-fi", ["ir-fi", "fi-de"])
        c = FailoverController(
            [MemberRuntime("m0", path_member_candidate(a), 1),
             MemberRuntime("m1", path_member_candidate(b), 2)],
            FailoverPolicy(failure_threshold=2))
        for _ in range(2):
            c.on_probe("m0", False)
        receipt = c.decide()
        assert receipt is not None
        assert c.members[receipt.to].candidate == "path:via-fi"
        # unselected path never activatable: it simply is not a member
        assert "path:via-xx" not in {m.candidate for m in c.members.values()}


class TestRoutingPlan:
    def test_plan_names_exact_nodes(self):
        topo = ir_tr_de_fg()
        plan = path_plan(topo, TopologyPath("p", ["ir-tr", "tr-de"]))
        assert plan[0]["node"] == "iran" and plan[1]["node"] == "turkey"
        text = str(plan)
        assert "fwmark" in text and "ENDPOINT-GUARD" in text and "MTU" in text
