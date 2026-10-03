"""Engine manifests + adapter SDK tests (P3) — unit_portable tier.

Fails on incomplete or contradictory manifests; enforces the catalog↔manifest
coverage invariant and the 12-method adapter contract.
"""
import copy
import json

import pytest

from engines import manifests as mf
from engines.adapters import (EngineAdapter, PlanAction, ProbeResult,
                              get_adapter, register_adapter, registered)

pytestmark = pytest.mark.unit_portable


@pytest.fixture(scope="module")
def all_manifests() -> dict[str, dict]:
    return mf.load_all()


class TestManifestValidation:
    def test_all_manifests_load_and_validate(self, all_manifests):
        assert len(all_manifests) == 21

    def test_catalog_engines_covered_by_manifests(self, all_manifests):
        from core.catalog import CATALOG
        catalog_engines = set(CATALOG.engines())
        assert catalog_engines == set(all_manifests), (
            f"missing manifests: {catalog_engines - set(all_manifests)}; "
            f"extra: {set(all_manifests) - catalog_engines}")

    def test_missing_field_fails(self, all_manifests):
        doc = copy.deepcopy(all_manifests["wireguard"])
        del doc["provides"]
        with pytest.raises(mf.ManifestError, match="provides"):
            mf.validate(doc)

    def test_unknown_capability_fails(self, all_manifests):
        doc = copy.deepcopy(all_manifests["wireguard"])
        doc["provides"] = ["L3_INTERFACE", "TELEPORT"]
        with pytest.raises(mf.ManifestError, match="unknown capabilities"):
            mf.validate(doc)

    def test_contradiction_tun_without_capability_fails(self, all_manifests):
        doc = copy.deepcopy(all_manifests["wireguard"])
        doc["provides"] = ["L3_INTERFACE"]            # TUN_INTERFACE removed
        with pytest.raises(mf.ManifestError, match="TUN_INTERFACE"):
            mf.validate(doc)

    def test_contradiction_udp_transport_requires_udp(self, all_manifests):
        doc = copy.deepcopy(all_manifests["wireguard"])
        doc["requires"] = ["TCP_STREAM"]               # udp wire but no UDP requirement
        with pytest.raises(mf.ManifestError, match="UDP_DATAGRAM not required"):
            mf.validate(doc)

    def test_contradiction_l3_layer_needs_l3_interface(self, all_manifests):
        doc = copy.deepcopy(all_manifests["gre"])
        doc["layer"] = "L3"
        doc["provides"] = ["SOCKS5_PROXY"]
        doc["raw_ip"] = False                            # isolate the layer contradiction
        with pytest.raises(mf.ManifestError, match="L3_INTERFACE"):
            mf.validate(doc)

    def test_bad_mtu_fails(self, all_manifests):
        doc = copy.deepcopy(all_manifests["gost"])
        doc["mtu_overhead"] = -5
        with pytest.raises(mf.ManifestError, match="mtu_overhead"):
            mf.validate(doc)

    def test_bad_verification_level_fails(self, all_manifests):
        doc = copy.deepcopy(all_manifests["gost"])
        doc["verification"] = "TOTALLY_VERIFIED"
        with pytest.raises(mf.ManifestError, match="verification"):
            mf.validate(doc)

    def test_nesting_requires_underlay(self, all_manifests):
        doc = copy.deepcopy(all_manifests["gost"])
        doc["can_be_underlay"] = False                 # nested stays True -> contradiction
        with pytest.raises(mf.ManifestError, match="can_be_nested"):
            mf.validate(doc)

    def test_wireguard_requirable_by_udp_providers(self, all_manifests):
        # spec invariant: WireGuard requires UDP_DATAGRAM; FRP_UDP provides it
        wg = all_manifests["wireguard"]
        frp = all_manifests["frp"]
        assert "UDP_DATAGRAM" in wg["requires"]
        assert "UDP_DATAGRAM" in frp["provides"]

    def test_gre_over_plain_socks_is_invalid_by_capabilities(self, all_manifests):
        # GRE requires RAW_IP; plain socks providers do not provide RAW_IP
        gre = all_manifests["gre"]
        ssh_manifest = all_manifests["ssh"]
        assert "RAW_IP" in gre["requires"]
        assert "RAW_IP" not in ssh_manifest["provides"]


class TestManifestFiles:
    def test_filenames_match_ids(self, tmp_path, all_manifests):
        for eid, doc in all_manifests.items():
            path = mf.MANIFESTS_DIR / f"{eid}.json"
            on_disk = json.loads(path.read_text(encoding="utf-8"))
            assert on_disk["id"] == eid
            mf.validate(on_disk)

    def test_load_all_rejects_id_filename_mismatch(self, tmp_path, all_manifests):
        # the filename↔id guard makes duplicate ids structurally impossible
        dup = copy.deepcopy(all_manifests["gre"])
        (tmp_path / "gre2.json").write_text(json.dumps({**dup, "id": "gre"}), encoding="utf-8")
        with pytest.raises(mf.ManifestError, match="must match filename"):
            mf.load_all(tmp_path)


class TestAdapterSDK:
    def test_full_contract_is_abstract(self):
        with pytest.raises(TypeError):
            EngineAdapter({}, {})                       # cannot instantiate ABC

    def test_register_rejects_partial_implementation(self):
        class Partial(EngineAdapter):
            engine_id = "half-baked"
            # implements nothing

        with pytest.raises(TypeError, match="does not implement detect"):
            register_adapter(Partial)

    def test_register_and_lookup(self):
        @register_adapter
        class FakeDemo(EngineAdapter):
            engine_id = "sdk-demo"                    # unique: never collides with real engines
            profile_id = "fake"

            def detect(self): return True
            def inventory(self): return {}
            def precheck(self): return []
            def plan(self): return [PlanAction("CREATE", "fake")]
            def install(self): pass
            def configure(self): pass
            def start(self): pass
            def probe(self): return ProbeResult(ok=True, evidence="fake 200 OK")
            def metrics(self): return {}
            def stop(self): pass
            def remove(self): pass
            def rollback(self): pass

        assert ("sdk-demo", "fake") in registered()
        assert get_adapter("sdk-demo", "fake") is FakeDemo
        # fallback: any profile of the engine
        assert get_adapter("sdk-demo", "nonexistent-profile") is FakeDemo
        with pytest.raises(KeyError):
            get_adapter("no-such-engine")

    def test_probe_result_semantics(self):
        r = ProbeResult(ok=False, evidence="no traffic passed")
        assert r.via == "data-plane" and not r.ok
