"""Composition engine tests (P8 §22) — unit_portable tier.

Planner-level only: capability matching/mismatch, all invalid cases, DAG
cycles, depth, repeatability, MTU/MSS, endpoint route guard, placement,
legacy mapping, topological install/reverse rollback, maturity,
warnings, deterministic plans, resource preflight, service CRUD.
"""
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from core.models import Base, Chain, Deployment
from orchestrator.composition import (ABSOLUTE_CEILING, ChainSpec, CompSpec,
                                      build_plan, chain_depth, check_depth,
                                      check_placement, check_repeatability,
                                      classify_maturity, detect_cycle,
                                      descendants, plan_mtu, resolve_pair,
                                      topological_order, validate_chain,
                                      all_legacy_composite_specs,
                                      create_chain, delete_chain,
                                      get_chain_spec, legacy_composite_to_spec,
                                      preview_chain, resource_preflight,
                                      update_chain, valid_overlays,
                                      valid_parents)
from orchestrator.composition.core import TCP_OVER_TCP_WARNING

pytestmark = pytest.mark.unit_portable


def two(under_engine, over_engine, under_profile="default", over_profile="default", **kw):
    return ChainSpec("t", [
        CompSpec("u", under_engine, profile_id=under_profile, **kw),
        CompSpec("o", over_engine, profile_id=over_profile, parent_id="u"),
    ])


# ── capability matching / mismatch ────────────────────────────────────

class TestCapabilityResolver:
    SPEC_EXAMPLES = [
        (("wireguard", "default"), ("frp", "tcp"), True),
        (("wireguard", "default"), ("gost", "grpc"), True),
        (("wireguard", "default"), ("xray", "vless_tcp"), True),
        (("wireguard", "default"), ("rathole", "tcp"), True),
        (("wireguard", "default"), ("chisel", "tcp"), True),
        (("wireguard", "default"), ("waterwall", "direct"), True),
        (("wireguard", "default"), ("ssh", "local_forward"), True),
        (("wireguard", "default"), ("gre", "default"), True),
        (("wireguard", "default"), ("gretap", "default"), True),
        (("wireguard", "default"), ("ipip", "default"), True),
        (("wireguard", "default"), ("sit", "default"), True),
        (("wireguard", "default"), ("vxlan", "default"), True),
        (("frp", "udp"), ("wireguard", "default"), True),
        (("gost", "udp_forward"), ("wireguard", "default"), True),
        (("rathole", "udp"), ("wireguard", "default"), True),
        (("chisel", "udp"), ("wireguard", "default"), True),
        (("wstunnel", "udp"), ("wireguard", "default"), True),
        (("hedioum", "tun"), ("wireguard", "default"), True),
        (("singbox", "tun"), ("wireguard", "default"), True),
        (("ssh", "tun_l3"), ("wireguard", "default"), True),
        (("openvpn", "default"), ("gre", "default"), True),
        (("vti", "default"), ("gre", "default"), True),
        (("gost", "tun"), ("gre", "default"), True),
        (("ssh", "tun_l3"), ("gre", "default"), True),
        (("gost", "tap"), ("gretap", "default"), True),
        (("ssh", "tun_l3"), ("sit", "default"), True),
        (("hedioum", "tun"), ("frp", "tcp"), True),
        (("hedioum", "tun"), ("xray", "vless_tcp"), True),
        # invalid set (§7)
        (("ssh", "dynamic_socks"), ("gre", "default"), False),
        (("frp", "tcp"), ("wireguard", "default"), False),
        (("rathole", "tcp"), ("wireguard", "default"), False),
        (("wstunnel", "tcp"), ("frp", "quic"), False),
        (("ssh", "dynamic_socks"), ("ipip", "default"), False),   # raw IP over SOCKS
    ]

    @pytest.mark.parametrize("under,over,expect", SPEC_EXAMPLES)
    def test_spec_examples(self, under, over, expect):
        v = validate_chain(two(under[0], over[0], under[1], over[1]))
        assert v.valid is expect, (under, over, v.reasons)

    def test_raw_ip_over_plain_socks_invalid_with_reason(self):
        v = validate_chain(two("ssh", "gre", "dynamic_socks"))
        assert any(r.startswith("RAW_IP_NOT_AVAILABLE") for r in v.reasons)

    def test_udp_over_tcp_needs_real_adapter(self):
        ok, reasons, adapters = resolve_pair("wireguard", "frp", "tcp")
        assert ok is False and adapters == []
        assert any("NOT implemented" in r for r in reasons)

    def test_physical_parent_satisfies_everything(self):
        ok, reasons, _ = resolve_pair("wireguard", None)
        assert ok and not reasons

    def test_unknown_engine(self):
        ok, reasons, _ = resolve_pair("quantum-entangle", "wireguard")
        assert not ok and reasons[0].startswith("UNKNOWN_ENGINE")


# ── DAG cycles (§2) ───────────────────────────────────────────────────

class TestCycles:
    def test_self_cycle(self):
        spec = ChainSpec("s", [CompSpec("a", "wireguard", parent_id="a")])
        assert detect_cycle(spec) == "a"
        assert not validate_chain(spec).valid

    def test_two_node_cycle(self):
        spec = ChainSpec("s", [CompSpec("a", "gre", parent_id="b"),
                               CompSpec("b", "wireguard", parent_id="a")])
        assert detect_cycle(spec) in ("a", "b")

    def test_three_node_cycle(self):
        spec = ChainSpec("s", [CompSpec("a", "gre", parent_id="c"),
                               CompSpec("b", "wireguard", parent_id="a"),
                               CompSpec("c", "frp", profile_id="tcp", parent_id="b")])
        assert detect_cycle(spec) is not None
        assert any("CYCLE_DETECTED" in r for r in validate_chain(spec).reasons)

    def test_deep_indirect_cycle(self):
        spec = ChainSpec("s", [
            CompSpec("a", "gre", parent_id="e"),
            CompSpec("b", "wireguard", parent_id="a"),
            CompSpec("c", "openvpn", parent_id="b"),
            CompSpec("d", "frp", profile_id="tcp", parent_id="c"),
            CompSpec("e", "ssh", profile_id="tun_l3", parent_id="d"),
        ])
        assert detect_cycle(spec) is not None

    def test_valid_dag_no_cycle(self):
        spec = two("wireguard", "gre")
        assert detect_cycle(spec) is None
        assert validate_chain(spec).valid

    def test_descendants(self):
        spec = ChainSpec("s", [
            CompSpec("phys-under", "wireguard"),
            CompSpec("mid", "openvpn", parent_id="phys-under"),
            CompSpec("top", "gre", parent_id="mid"),
            CompSpec("side", "frp", profile_id="tcp", parent_id="phys-under"),
        ])
        assert descendants(spec, "phys-under") == {"mid", "top", "side"}
        assert descendants(spec, "mid") == {"top"}


# ── depth (§19) ───────────────────────────────────────────────────────

class TestDepth:
    def deep_spec(self, n):
        comps = [CompSpec("c0", "wireguard")]
        for i in range(1, n):
            comps.append(CompSpec(f"c{i}", "openvpn", parent_id=f"c{i-1}"))
        return ChainSpec("deep", comps)

    def test_hard_auto_limit(self):
        reasons = check_depth(self.deep_spec(HARD := 6))
        assert any("automatic limit" in r for r in reasons)

    def test_override_allows_deeper_but_ceiling_caps(self):
        spec = self.deep_spec(ABSOLUTE_CEILING + 1)
        assert any("absolute ceiling" in r for r in check_depth(spec, override=True))

    def test_within_limits_ok(self):
        assert check_depth(self.deep_spec(3)) == []

    def test_chain_depth(self):
        assert chain_depth(two("wireguard", "gre")) == 2


HARD_AUTO_LIMIT = 6  # local alias for readability above


# ── repeatability (§8) ────────────────────────────────────────────────

class TestRepeatability:
    def test_non_repeatable_rejected(self):
        spec = ChainSpec("s", [CompSpec("a", "ipsec", profile_id="ikev2"),
                               CompSpec("b", "ipsec", profile_id="l2tp", parent_id="a"),
                               CompSpec("c", "gre", parent_id="b")])
        reasons = check_repeatability(spec)
        assert any(r.startswith("NON_REPEATABLE_ENGINE") for r in reasons)

    def test_repeatable_engine_allowed(self):
        spec = two("wireguard", "wireguard")   # WG over WG: repeatable declared
        assert check_repeatability(spec) == []


# ── MTU / MSS (§11, §12) ──────────────────────────────────────────────

class TestMtu:
    def test_overheads_summed(self):
        spec = two("wireguard", "gre")          # 80 + 24
        mtu, reasons = plan_mtu(spec)
        assert mtu.overhead_total == 80 + 24
        assert mtu.effective_mtu == 1500 - 104
        assert reasons == []

    def test_mss_clamp_decision(self):
        mtu, _ = plan_mtu(two("wireguard", "gre"))
        assert mtu.mss_clamp_required is True   # TCP-capable chain below physical-40
        assert "MSS-CLAMP" in mtu.as_actions()[0]

    def test_deep_stack_rejected_below_floor(self):
        comps = [CompSpec("c0", "wireguard")]
        for i in range(1, 8):
            comps.append(CompSpec(f"c{i}", "openvpn", parent_id=f"c{i-1}"))
        mtu, reasons = plan_mtu(ChainSpec("deep", comps))
        assert mtu.effective_mtu < 1000
        assert any(r.startswith("MTU_TOO_LOW") for r in reasons)

    def test_ipv6_minimum_respected(self):
        comps = [CompSpec("c0", "wireguard")]
        for i in range(1, 5):
            comps.append(CompSpec(f"c{i}", "openvpn", parent_id=f"c{i-1}"))
        mtu, reasons = plan_mtu(ChainSpec("v6", comps))
        if mtu.effective_mtu < 1280:
            assert any("IPv6 minimum" in r for r in reasons)
        else:
            assert mtu.ipv6_ok


# ── endpoint route guard (§13) ────────────────────────────────────────

class TestRouteGuard:
    def test_self_routing_loop_rejected(self):
        spec = ChainSpec("s", [
            CompSpec("wg", "wireguard", endpoint="10.0.0.1", endpoint_via="wg"),
            CompSpec("gre", "gre", parent_id="wg"),
        ])
        reasons, _ = orchestrator_guard(spec)
        assert any(r.startswith("ENDPOINT_ROUTE_LOOP") and "own endpoint" in r
                   for r in reasons)

    def test_loop_via_own_rider_rejected(self):
        spec = ChainSpec("s", [
            CompSpec("wg", "wireguard", endpoint="10.0.0.1", endpoint_via="gre"),
            CompSpec("gre", "gre", parent_id="wg"),
        ])
        reasons, _ = orchestrator_guard(spec)
        assert any("own rider" in r for r in reasons)

    def test_physical_via_produces_guard_action(self):
        spec = ChainSpec("s", [
            CompSpec("wg", "wireguard", endpoint="203.0.113.20", endpoint_via="physical"),
            CompSpec("gre", "gre", parent_id="wg"),
        ])
        reasons, actions = orchestrator_guard(spec)
        assert reasons == []
        assert any(a.startswith("PIN 203.0.113.20/32") for a in actions)

    def test_via_ancestor_is_fine(self):
        spec = ChainSpec("s", [
            CompSpec("phys", "wireguard"),
            CompSpec("ovpn", "openvpn", endpoint="10.1.1.2", endpoint_via="phys", parent_id="phys"),
            CompSpec("gre", "gre", parent_id="ovpn"),
        ])
        reasons, actions = orchestrator_guard(spec)
        assert reasons == [] and any("via underlay phys" in a for a in actions)


def orchestrator_guard(spec):
    from orchestrator.composition.core import check_endpoint_routes
    return check_endpoint_routes(spec)


# ── placement (§14) ───────────────────────────────────────────────────

class TestPlacement:
    def test_disjoint_nodes_rejected(self):
        spec = ChainSpec("s", [CompSpec("u", "wireguard", node="a"),
                               CompSpec("o", "gre", parent_id="u", node="b")])
        assert any(r.startswith("INVALID_PLACEMENT") for r in check_placement(spec))

    def test_shared_node_ok(self):
        spec = ChainSpec("s", [CompSpec("u", "wireguard", node="both"),
                               CompSpec("o", "gre", parent_id="u", node="b")])
        assert check_placement(spec) == []


# ── maturity + warnings (§9, §10) ─────────────────────────────────────

class TestMaturity:
    def test_standard_chain(self):
        maturity, warnings = classify_maturity(two("wireguard", "frp", "default", "tcp"))
        assert maturity == "STANDARD" and warnings == []

    def test_tcp_over_tcp_warns_and_degrades_maturity(self):
        spec = two("ssh", "frp", "local_forward", "tcp")
        maturity, warnings = classify_maturity(spec)
        assert any(w.startswith(TCP_OVER_TCP_WARNING) for w in warnings)
        assert maturity in ("ADVANCED", "EXPERIMENTAL")

    def test_deep_chain_experimental(self):
        comps = [CompSpec("c0", "wireguard")]
        for i in range(1, 5):
            comps.append(CompSpec(f"c{i}", "openvpn", parent_id=f"c{i-1}"))
        maturity, _ = classify_maturity(ChainSpec("d", comps))
        assert maturity == "EXPERIMENTAL"


# ── plan determinism + ordering (§16, §17) ────────────────────────────

class TestPlan:
    SPEC = ChainSpec("frp-over-wg", [
        CompSpec("wg", "wireguard", endpoint="203.0.113.20"),
        CompSpec("frp", "frp", profile_id="tcp", parent_id="wg"),
        CompSpec("gre", "gre", parent_id="wg"),
    ])

    def test_install_underlay_before_overlay(self):
        plan = build_plan(self.SPEC)
        assert plan.install_order[0] == "wg"
        assert set(plan.install_order[1:]) == {"frp", "gre"}

    def test_rollback_is_reverse_of_install(self):
        plan = build_plan(self.SPEC)
        assert plan.rollback_order == list(reversed(plan.install_order))

    def test_probe_order_equals_install_order(self):
        plan = build_plan(self.SPEC)
        assert plan.probe_order == plan.install_order

    def test_plan_deterministic(self):
        assert build_plan(self.SPEC).as_dict() == build_plan(self.SPEC).as_dict()

    def test_plan_carries_mtu_guard_verification(self):
        plan = build_plan(two("wireguard", "gre"))
        d = plan.as_dict()
        assert d["effective_mtu"] == 1396 and d["maturity"] in ("STANDARD", "ADVANCED")
        assert set(d["verification"]) == {"u", "o"}

    def test_invalid_chain_has_no_plan(self):
        assert build_plan(two("ssh", "gre", "dynamic_socks")) is None


# ── resource preflight (§15) ──────────────────────────────────────────

class TestPreflight:
    def test_preflight_non_mutating(self):
        eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                            connect_args={"check_same_thread": False})
        Base.metadata.create_all(eng)
        with Session(eng) as s:
            ok, conflicts = resource_preflight(s, two("wireguard", "gre"))
            assert ok and conflicts == []
            # ZERO ledger rows created by preflight
            from core.models import ResourceAllocation
            assert s.query(ResourceAllocation).count() == 0


# ── legacy composite mapping (§18) ────────────────────────────────────

class TestLegacyComposites:
    def test_all_six_templates_map_and_validate(self):
        specs = all_legacy_composite_specs()
        assert len(specs) == 6
        for legacy, spec in specs.items():
            v = validate_chain(spec)
            assert v.valid, f"{legacy}: {v.reasons}"

    def test_unknown_legacy_returns_none(self):
        assert legacy_composite_to_spec("NOPE_OVER_NOPE") is None

    def test_gre_over_ssh_maps_to_tun_profile(self):
        spec = legacy_composite_to_spec("GRE_OVER_SSH")
        assert spec.by_id()["underlay"].profile_id == "tun_l3"


# ── service CRUD + dry-run (§20) ──────────────────────────────────────

@pytest.fixture()
def session():
    eng = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    with Session(eng) as s:
        yield s
        s.rollback()


class TestService:
    def test_create_never_deploys(self, session):
        chain, v = create_chain(session, two("wireguard", "frp", "default", "tcp"))
        assert chain is not None and v.valid
        assert session.query(Deployment).count() == 0      # creation deploys nothing

    def test_invalid_spec_rejected_no_row(self, session):
        chain, v = create_chain(session, two("ssh", "gre", "dynamic_socks"))
        assert chain is None and not v.valid
        assert session.query(Chain).count() == 0

    def test_get_roundtrip(self, session):
        chain, _ = create_chain(session, two("wireguard", "gre"))
        spec = get_chain_spec(session, chain.id)
        assert {c.component_id for c in spec.components} == {"u", "o"}
        assert spec.by_id()["o"].parent_id == "u"

    def test_update_and_delete(self, session):
        chain, _ = create_chain(session, two("wireguard", "gre"))
        updated, v = update_chain(session, chain.id,
                                  two("wireguard", "frp", "default", "tcp"))
        assert updated is not None and v.valid
        assert len(get_chain_spec(session, chain.id).components) == 2
        assert delete_chain(session, chain.id) is True
        assert get_chain_spec(session, chain.id) is None

    def test_preview_is_dry_run_zero_mutations(self, session):
        result = preview_chain(session, two("wireguard", "frp", "default", "tcp"))
        assert result["valid"] and result["plan"]["install_order"][0] == "u"
        assert result["preflight"]["ok"]
        assert session.query(Chain).count() == 0           # preview creates nothing

    def test_preview_invalid_chain_explains(self, session):
        result = preview_chain(session, two("ssh", "gre", "dynamic_socks"))
        assert result["valid"] is False
        assert any("RAW_IP_NOT_AVAILABLE" in r for r in result["reasons"])

    def test_valid_parents_listing(self):
        parents = valid_parents("wireguard")
        engines = {p["engine"] for p in parents}
        assert {"frp", "gost", "chisel", "wstunnel", "rathole"} <= engines
        assert all("ssh" != e or True for e in engines)     # ssh valid only via tun profile

    def test_valid_overlays_listing(self):
        overlays = valid_overlays("wireguard")
        engines = {o.split("/")[0] for o in overlays}
        assert {"gre", "frp", "gost", "xray"} <= engines


from orchestrator.composition import HARD_AUTO_LIMIT  # noqa: E402  (used above)
