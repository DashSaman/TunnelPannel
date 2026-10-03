"""Composition engine: capability-driven chain validation and planning."""
from orchestrator.composition.core import (  # noqa: F401
    ABSOLUTE_CEILING, ChainSpec, CompSpec, CompositionPlan, HARD_AUTO_LIMIT,
    MtuPlan, RECOMMENDED_DEPTH, Validation, build_plan, chain_depth,
    check_depth, check_placement, check_repeatability, classify_maturity,
    detect_cycle, descendants, plan_mtu, resolve_pair, topological_order,
    validate_chain, check_endpoint_routes,
)
from orchestrator.composition.service import (  # noqa: F401
    all_legacy_composite_specs, create_chain, delete_chain, get_chain_spec,
    legacy_composite_to_spec, preview_chain, resource_preflight, update_chain,
    valid_overlays, valid_parents,
)
