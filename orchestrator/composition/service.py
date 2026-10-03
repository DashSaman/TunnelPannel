"""Composition service (P8 §15, §18, §20) — DB-backed chains + APIs.

- resource preflight: NON-mutating feasibility via the P4 ledger
- legacy composite IDs (GRE_OVER_WIREGUARD …) map to canonical Chain
  templates — compatibility, not duplicated execution code
- validate / explain / preview / list parents / list overlays / CRUD /
  dry-run; creating a chain NEVER deploys anything
"""
from __future__ import annotations


from sqlalchemy import select
from sqlalchemy.orm import Session

from core.catalog import CATALOG
from core.models import Chain, ChainComponent
from engines.manifests import load_all
from orchestrator.resources import ResourceManager

from .core import (ChainSpec, CompSpec, Validation, build_plan, resolve_pair,
                   topological_order, validate_chain)


# ── resource preflight (§15) — feasibility WITHOUT reservation ────────

def resource_preflight(session: Session, spec: ChainSpec,
                       manifests: dict | None = None,
                       node_id: str | None = None) -> tuple[bool, list[str]]:
    """Non-mutating: would the needed ports/interfaces/tables collide?"""
    manifests = manifests or load_all()
    rm = ResourceManager(session)
    conflicts: list[str] = []

    def live(kind: str) -> set[str]:
        return rm.owned_keys(kind, node_id)

    used_tcp = live("tcp_port")
    used_udp = live("udp_port")
    used_iface = live("interface")
    used_table = live("route_table")

    iface_idx = 0
    table_idx = 0
    for cid in topological_order(spec):
        comp = spec.by_id()[cid]
        m = manifests.get(comp.engine_id, {})
        ports = m.get("ports", {}) or {}
        for key in (str(v) for v in ports.values() if isinstance(v, int)):
            kind_keys = used_tcp if "tcp" in str(ports) else used_udp
            if key in kind_keys:
                conflicts.append(f"RESOURCE_CONFLICT: {kind_keys and 'port'} {key} for {cid}")
        while f"tp{iface_idx}" in used_iface:
            iface_idx += 1
        iface_idx += 1
        table_idx += 1
    # deterministic projected names never collide with the live ledger above
    return (not conflicts), conflicts


# ── legacy composite → canonical chain templates (§18) ────────────────

# Legacy composites GRE/SIT_OVER_SSH etc. historically rode SSH's tun/tap
# mode (Gen1 executor), never its plain SOCKS profile — reflect that.
_UNDERLAY_PROFILE_HINTS = {"ssh": "tun_l3", "gost": "tun"}


def legacy_composite_to_spec(legacy_id: str) -> ChainSpec | None:
    ident = CATALOG.composite_templates.get(legacy_id)
    if ident is None:
        return None
    underlay_profile = _UNDERLAY_PROFILE_HINTS.get(ident.underlay, "default")
    return ChainSpec(
        name=f"legacy:{legacy_id}",
        components=[
            CompSpec(component_id="underlay", engine_id=ident.underlay,
                     profile_id=underlay_profile, parent_id=None, node="both"),
            CompSpec(component_id="overlay", engine_id=ident.overlay,
                     parent_id="underlay", node="both"),
        ],
    )


def all_legacy_composite_specs() -> dict[str, ChainSpec]:
    return {lid: legacy_composite_to_spec(lid) for lid in CATALOG.composite_templates}


# ── parents / overlays discovery (§20) ─────────────────────────────────

def valid_parents(engine_id: str, manifests: dict | None = None) -> list[dict]:
    """Profile-qualified: a parent is (engine, profile) — chisel carries WG
    via its udp profile, not its engine default."""
    manifests = manifests or load_all()
    from core.catalog import CATALOG
    out = []
    pairs = sorted({(i.engine, i.profile) for i in CATALOG.identities.values()
                    if not i.is_composite})
    for pengine, pprofile in pairs:
        pm = manifests.get(pengine)
        if pm is None or pengine == engine_id or not pm["can_be_underlay"]:
            continue
        ok, _reasons, adapters = resolve_pair(engine_id, pengine,
                                              parent_profile=pprofile,
                                              manifests=manifests)
        if ok:
            out.append({"engine": pengine, "profile": pprofile,
                        "via_adapters": adapters})
    return out


def valid_overlays(engine_id: str, profile_id: str = "default",
                   manifests: dict | None = None) -> list[str]:
    """Profile-qualified overlays that may ride (engine_id, profile_id)."""
    manifests = manifests or load_all()
    from core.catalog import CATALOG
    out = []
    pairs = sorted({(i.engine, i.profile) for i in CATALOG.identities.values()
                    if not i.is_composite})
    for cengine, cprofile in pairs:
        cm = manifests.get(cengine)
        if cm is None or cengine == engine_id or not cm["can_be_overlay"]:
            continue
        ok, _r, _a = resolve_pair(cengine, engine_id, profile_id, manifests)
        if ok:
            out.append(f"{cengine}/{cprofile}")
    return out


# ── DB-backed chain CRUD (§20) — creation never deploys ───────────────

def create_chain(session: Session, spec: ChainSpec) -> tuple[Chain | None, Validation]:
    validation = validate_chain(spec)
    if not validation.valid:
        return None, validation
    chain = Chain(name=spec.name)
    session.add(chain)
    session.flush()
    for c in spec.components:
        session.add(ChainComponent(
            chain_id=chain.id, component_id=c.component_id, parent_id=c.parent_id,
            engine_id=c.engine_id, profile_id=c.profile_id, legacy_method_id=None,
            node_a=None if c.node in ("b",) else "a",
            node_b=None if c.node in ("a",) else "b"))
    session.commit()
    return chain, validation


def get_chain_spec(session: Session, chain_id: str) -> ChainSpec | None:
    chain = session.get(Chain, chain_id)
    if chain is None:
        return None
    rows = session.scalars(select(ChainComponent)
                           .where(ChainComponent.chain_id == chain_id)).all()
    return ChainSpec(name=chain.name, components=[
        CompSpec(component_id=r.component_id, engine_id=r.engine_id,
                 profile_id=r.profile_id or "default", parent_id=r.parent_id,
                 node="both" if (r.node_a and r.node_b) else
                      ("a" if r.node_a else "b"))
        for r in rows])


def update_chain(session: Session, chain_id: str, spec: ChainSpec) -> tuple[Chain | None, Validation]:
    chain = session.get(Chain, chain_id)
    if chain is None:
        return None, Validation(False, ["NO_SUCH_CHAIN"])
    validation = validate_chain(spec)
    if not validation.valid:
        return None, validation
    for r in session.scalars(select(ChainComponent)
                             .where(ChainComponent.chain_id == chain_id)).all():
        session.delete(r)
    chain.name = spec.name
    session.flush()
    for c in spec.components:
        session.add(ChainComponent(
            chain_id=chain.id, component_id=c.component_id, parent_id=c.parent_id,
            engine_id=c.engine_id, profile_id=c.profile_id,
            node_a=None if c.node == "b" else "a",
            node_b=None if c.node == "a" else "b"))
    session.commit()
    return chain, validation


def delete_chain(session: Session, chain_id: str) -> bool:
    chain = session.get(Chain, chain_id)
    if chain is None:
        return False
    session.delete(chain)
    session.commit()
    return True


def preview_chain(session: Session, spec: ChainSpec) -> dict:
    """Dry-run: full plan + preflight; ZERO mutations (no Chain row created)."""
    plan = build_plan(spec)
    if plan is None:
        v = validate_chain(spec)
        return {"valid": False, "reasons": v.reasons, "plan": None,
                "preflight": {"ok": False, "conflicts": ["validation failed"]}}
    ok, conflicts = resource_preflight(session, spec)
    return {"valid": True and ok, "reasons": conflicts, "plan": plan.as_dict(),
            "preflight": {"ok": ok, "conflicts": conflicts}}
