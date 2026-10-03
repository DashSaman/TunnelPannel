"""Canonical engine/method counts — single source of truth (consistency gate B).

Every number reported anywhere must come from HERE (computed live), with
invariant tests (tests/unit/test_counts.py) that fail on drift.

History note — why "22 engines" was once reported: the catalog's
``Catalog.engines()`` initially included the ``composite`` pseudo-engine;
it was excluded during P2. The honest set is 21 real engines + the
``composite`` pseudo-family for templates.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.catalog import CATALOG

PSEUDO_ENGINES = frozenset({"composite", "_abstract"})


@dataclass(frozen=True)
class CanonicalCounts:
    legacy_method_ids: int            # registry entries (Gen2 superset)
    canonical_engines: int            # real engines (pseudo excluded)
    engine_profiles: int              # non-composite identities
    composite_templates: int
    aliases: int                      # extra resolvable legacy names
    total_resolvable_legacy_ids: int

    def as_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


def compute_counts(catalog=CATALOG) -> CanonicalCounts:
    identities = catalog.identities
    composites = catalog.composite_templates
    profiles = sum(1 for i in identities.values() if not i.is_composite)
    engines = len(catalog.engines())               # pseudo already excluded
    aliases = len(_alias_map(catalog))
    return CanonicalCounts(
        legacy_method_ids=len(identities),         # 82 (includes 6 composites)
        canonical_engines=engines,                 # 21
        engine_profiles=profiles,                  # 76
        composite_templates=len(composites),       # 6
        aliases=aliases,                           # 6 Gen3 bare names
        total_resolvable_legacy_ids=len(identities) + aliases,   # 88
    )


def _alias_map(catalog) -> dict[str, str]:
    """Resolvable alias names not part of the registry itself."""
    from core.catalog import _LEGACY_ALIASES
    return dict(_LEGACY_ALIASES)


COUNTS = compute_counts()
