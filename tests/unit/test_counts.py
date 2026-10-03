"""Canonical count invariants (consistency gate B) — drift detector.

These exact numbers change ONLY by deliberate decision (new engine,
removed method…). If a test here fails unexpectedly, a catalog/manifest
change introduced drift — investigate before updating the expected value.
"""
import pytest

from core.catalog import CATALOG
from core.counts import COUNTS, PSEUDO_ENGINES, compute_counts

pytestmark = pytest.mark.unit_portable


class TestCanonicalCounts:
    def test_legacy_method_ids(self):
        assert COUNTS.legacy_method_ids == 82          # registry incl. 6 composites

    def test_canonical_engines(self):
        assert COUNTS.canonical_engines == 21          # real engines, pseudo excluded

    def test_engine_profiles(self):
        assert COUNTS.engine_profiles == 76

    def test_composite_templates(self):
        assert COUNTS.composite_templates == 6

    def test_aliases(self):
        assert COUNTS.aliases == 6                     # Gen3 bare adapter names

    def test_total_resolvable_legacy_ids(self):
        assert COUNTS.total_resolvable_legacy_ids == 88

    def test_arithmetic_consistency(self):
        assert COUNTS.engine_profiles + COUNTS.composite_templates \
            == COUNTS.legacy_method_ids
        assert COUNTS.total_resolvable_legacy_ids \
            == COUNTS.legacy_method_ids + COUNTS.aliases

    def test_pseudo_engines_never_counted(self):
        engines = {i.engine for i in CATALOG.identities.values()}
        assert engines & PSEUDO_ENGINES == {"composite"}   # composite exists only as family
        assert not (set(CATALOG.engines()) & PSEUDO_ENGINES)

    def test_compute_is_deterministic(self):
        assert compute_counts() == COUNTS

    def test_every_profile_resolves_to_adapter(self):
        from engines.adapters import get_adapter
        import engines.adapters.kernel          # noqa: F401
        import engines.adapters.kernel_extra    # noqa: F401
        import engines.adapters.ssh_family      # noqa: F401
        import engines.adapters.userspace       # noqa: F401
        n = 0
        for ident in CATALOG.identities.values():
            if ident.is_composite:
                continue
            assert get_adapter(ident.engine, ident.profile) is not None
            n += 1
        assert n == COUNTS.engine_profiles
