"""Canonical catalog identity tests (P2) — unit_portable tier.

Covers: full coverage of registry IDs, engine/profile split rules, legacy
alias round-trip, composite semantics (A over B = A uses B as underlay).
"""
import pytest

from core.catalog import CATALOG, MethodIdentity, load_catalog

pytestmark = pytest.mark.unit_portable


class TestCoverage:
    def test_every_registry_method_has_identity(self):
        # Gen2 registry is the 82-entry superset
        assert len(CATALOG.identities) == 82

    def test_no_identity_collisions(self):
        seen = {}
        for ident in CATALOG.identities.values():
            if ident.is_composite:
                continue
            key = (ident.engine, ident.profile)
            assert key not in seen, f"collision {key}: {seen[key].legacy_id} vs {ident.legacy_id}"
            seen[key] = ident

    def test_engines_exclude_pseudo(self):
        engines = CATALOG.engines()
        assert "composite" not in engines
        assert not any(e.startswith("_") for e in engines)

    def test_expected_engine_set(self):
        engines = set(CATALOG.engines())
        for expected in ("wireguard", "gre", "gretap", "ipip", "sit", "vti", "vxlan",
                         "openvpn", "ipsec", "ssh", "gost", "xray", "singbox", "frp",
                         "rathole", "chisel", "wstunnel", "waterwall", "paqet",
                         "hedioum", "hajsaman"):
            assert expected in engines, f"missing engine {expected}"


class TestIdentitySplit:
    def test_gost_variants_are_profiles_of_one_engine(self):
        profiles = set(CATALOG.profiles_of("gost"))
        assert len(profiles) == 15
        assert {"grpc", "quic", "ws", "tun", "tap", "ssh"} <= profiles

    def test_kernel_variants(self):
        assert CATALOG.by_legacy("IP6GRE") == MethodIdentity(
            "IP6GRE", "gre", "ip6", "KERNEL_BASE", "IP6GRE")
        assert CATALOG.by_legacy("VTI6").profile == "v6"
        assert CATALOG.by_legacy("SIT_6IN4").engine == "sit"

    def test_xray_profiles(self):
        ident = CATALOG.by_legacy("VLESS_XHTTP_REALITY")
        assert (ident.engine, ident.profile) == ("xray", "xhttp_reality")

    def test_ssh_profiles(self):
        for legacy in ("SSH_LOCAL_FORWARD", "SSH_DYNAMIC_SOCKS", "SSH_TUN_L3",
                       "SSH_TAP_L2", "AUTOSSH_REVERSE"):
            assert CATALOG.by_legacy(legacy).engine == "ssh"
        assert CATALOG.by_legacy("AUTOSSH_REVERSE").profile == "reverse"

    def test_gen3_bare_names_alias_to_canonical_ids(self):
        assert CATALOG.by_legacy("HEDIOUM").legacy_id == "HEDIOUM_TUN"
        assert CATALOG.by_legacy("HAJSAMAN").legacy_id == "HAJSAMAN_FULL"
        assert CATALOG.by_legacy("PAQET").legacy_id == "PAQET_SOCKS5"
        assert CATALOG.by_legacy("SIT").legacy_id == "SIT_6IN4"
        # aliases do not inflate the canonical method count
        assert len(CATALOG.identities) == 82

    def test_resolve_round_trip(self):
        ident = CATALOG.resolve("gost", "grpc")
        assert ident is not None and ident.legacy_id == "GOST_GRPC"

    def test_unknown_id_raises(self):
        with pytest.raises(KeyError):
            CATALOG.by_legacy("NO_SUCH_METHOD")


class TestComposites:
    def test_composite_count_and_semantics(self):
        assert len(CATALOG.composite_templates) == 6
        ident = CATALOG.by_legacy("GRE_OVER_WIREGUARD")
        assert ident.is_composite
        # canonical semantics: GRE uses WireGuard as its underlay/carrier
        assert (ident.overlay, ident.underlay) == ("gre", "wireguard")

    def test_registry_ids_stay_addressable(self):
        for legacy in ("GRE_OVER_SSH", "SIT_OVER_GOST", "GRETAP_OVER_GOST"):
            assert legacy in CATALOG.identities


class TestReload:
    def test_load_catalog_is_deterministic(self):
        c1, c2 = load_catalog(), load_catalog()
        assert sorted(c1.identities) == sorted(c2.identities)
