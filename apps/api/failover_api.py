"""Failover group HTTP API (P10 §57).

Membership is fixed at creation (the operator's selection IS the group —
nothing unselected can ever join). Controllers are pure decision engines
fed by probes; production probe wiring arrives with P12 monitoring.
"""
from __future__ import annotations

import dataclasses

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.models import Event, FailoverGroup, FailoverMember
from core.security import record_audit
from orchestrator.failover import (FailoverController, FailoverPolicy,
                                   MemberRuntime, diversity_recommendation,
                                   diversity_warnings)
from orchestrator.composition import ChainSpec, CompSpec

router_registry: dict[str, FailoverController] = {}


class MemberBody(BaseModel):
    candidate: str
    priority: int
    kind: str = "single"


class GroupBody(BaseModel):
    name: str
    members: list[MemberBody]
    mode: str = "MANUAL_PRIORITY"
    preemption: str = "NO_PREEMPT"
    failure_threshold: int = 3
    recovery_threshold: int = 3
    cooldown_s: float = 30.0


class ProbeBody(BaseModel):
    member_index: int
    ok: bool


class PinBody(BaseModel):
    member_index: int | None = None


class MaintenanceBody(BaseModel):
    member_index: int
    on: bool


def _spec_for(candidate: str) -> ChainSpec | None:
    """Diversity analysis works on chain specs; single routes map to a
    one-component spec so shared-underlay math still applies."""
    if candidate.startswith("chain:"):
        return None                                 # resolved by caller with session
    from core.catalog import CATALOG
    try:
        ident = CATALOG.by_legacy(candidate)
    except KeyError:
        return None
    return ChainSpec(candidate, [CompSpec("solo", ident.engine,
                                          profile_id=ident.profile)])


def create_router(session_factory) -> APIRouter:
    router = APIRouter(prefix="/failover-groups", tags=["failover"])

    @router.post("")
    def create_group(body: GroupBody):
        if not body.members:
            raise HTTPException(400, "a failover group needs at least one member")
        priorities = [m.priority for m in body.members]
        if len(set(priorities)) != len(priorities):
            raise HTTPException(400, "member priorities must be unique")
        if body.mode not in ("MANUAL_PRIORITY", "SCORE_PRIORITY"):
            raise HTTPException(400, "mode must be MANUAL_PRIORITY|SCORE_PRIORITY")
        if body.preemption not in ("NO_PREEMPT", "PREFER_PRIMARY", "BEST_SCORE"):
            raise HTTPException(400, "unknown preemption policy")

        specs = [_spec_for(m.candidate) for m in sorted(body.members,
                                                        key=lambda m: m.priority)]
        with session_factory() as session:
            group = FailoverGroup(
                name=body.name, mode=body.mode, preemption=body.preemption,
                failure_threshold=body.failure_threshold,
                recovery_threshold=body.recovery_threshold,
                cooldown_s=int(body.cooldown_s))
            session.add(group)
            session.flush()
            for m in body.members:
                session.add(FailoverMember(group_id=group.id, priority=m.priority,
                                           candidate=m.candidate,
                                           candidate_kind=m.kind))
            session.commit()
            group_id = group.id

        record_audit(session_factory, "operator", "failover.group_create",
                     target=body.name,
                     detail={"members": [m.candidate for m in body.members],
                             "mode": body.mode})
        policy = FailoverPolicy(mode=body.mode, preemption=body.preemption,
                                failure_threshold=body.failure_threshold,
                                recovery_threshold=body.recovery_threshold,
                                cooldown_s=body.cooldown_s)
        runtime = [MemberRuntime(f"m{i}", m.candidate, m.priority)
                   for i, m in enumerate(sorted(body.members, key=lambda x: x.priority))]
        controller = FailoverController(runtime, policy)
        router_registry[group_id] = controller

        known = [x for x in specs if x is not None]
        warnings = diversity_warnings(known[0], known[1:]) if len(known) >= 2 else []
        recommendation = (diversity_recommendation(known[0], known[1:])
                          if len(known) >= 2 else None)
        return {"group_id": group_id, "active": controller.active,
                "diversity_warnings": warnings,
                "diversity_recommendation": recommendation}

    def _group(group_id: str, session):
        group = session.get(FailoverGroup, group_id)
        if group is None:
            raise HTTPException(404, "no such failover group")
        return group

    def _controller(group_id: str, session) -> FailoverController:
        if group_id not in router_registry:
            rows = session.query(FailoverMember).filter(
                FailoverMember.group_id == group_id).order_by(
                FailoverMember.priority).all()
            group = _group(group_id, session)
            if not rows:
                raise HTTPException(400, "group has no members")
            policy = FailoverPolicy(mode=group.mode, preemption=group.preemption,
                                    failure_threshold=group.failure_threshold,
                                    recovery_threshold=group.recovery_threshold,
                                    cooldown_s=float(group.cooldown_s))
            router_registry[group_id] = FailoverController(
                [MemberRuntime(f"m{i}", r.candidate, r.priority)
                 for i, r in enumerate(rows)], policy)
        return router_registry[group_id]

    @router.get("")
    def list_groups():
        with session_factory() as session:
            groups = session.query(FailoverGroup).all()
            return [{"id": g.id, "name": g.name, "mode": g.mode,
                     "preemption": g.preemption,
                     "active": router_registry[g.id].active if g.id in router_registry else None}
                    for g in groups]

    @router.get("/{group_id}")
    def group_state(group_id: str):
        with session_factory() as session:
            group = _group(group_id, session)
            c = _controller(group_id, session)
            members = session.query(FailoverMember).filter(
                FailoverMember.group_id == group_id).order_by(
                FailoverMember.priority).all()
            return {"id": group.id, "name": group.name, "mode": group.mode,
                    "preemption": group.preemption, "maintenance": group.maintenance,
                    "pinned": c.pinned, "active": c.active,
                    "members": [{"priority": m.priority, "candidate": m.candidate,
                                 "kind": m.candidate_kind,
                                 "healthy": c.members[f"m{i}"].ok}
                                for i, m in enumerate(members)]}

    @router.post("/{group_id}/probes")
    def feed_probe(group_id: str, body: ProbeBody):
        with session_factory() as session:
            _group(group_id, session)
            c = _controller(group_id, session)
            key = f"m{body.member_index}"
            if key not in c.members:
                raise HTTPException(404, f"no member index {body.member_index}")
            c.on_probe(key, body.ok)
            receipt = c.decide()
            if receipt is not None:
                session.add(Event(severity="info" if receipt.actor != "EMERGENCY" else "warn",
                                  source="failover",
                                  message=f"switch {receipt.frm} -> {receipt.to} "
                                          f"({receipt.actor}): {receipt.reason}",
                                  context={"group_id": group_id,
                                           "receipt": dataclasses.asdict(receipt)}))
                session.commit()
            return {"active": c.active, "switch": dataclasses.asdict(receipt)
                    if receipt else None}

    @router.post("/{group_id}/pin")
    def pin(group_id: str, body: PinBody):
        with session_factory() as session:
            _group(group_id, session)
            c = _controller(group_id, session)
            c.pin(None if body.member_index is None else f"m{body.member_index}")
            record_audit(session_factory, "operator", "failover.pin",
                         target=group_id, detail={"member_index": body.member_index})
            return {"pinned": c.pinned}

    @router.post("/{group_id}/maintenance")
    def maintenance(group_id: str, body: MaintenanceBody):
        with session_factory() as session:
            _group(group_id, session)
            c = _controller(group_id, session)
            key = f"m{body.member_index}"
            if key not in c.members:
                raise HTTPException(404, "no such member")
            c.set_maintenance(key, body.on)
            record_audit(session_factory, "operator", "failover.maintenance",
                         target=group_id, detail={"member": key, "on": body.on})
            receipt = c.decide()
            return {"maintenance": {k: m.maintenance for k, m in c.members.items()},
                    "switch": dataclasses.asdict(receipt) if receipt else None}

    @router.get("/{group_id}/history")
    def history(group_id: str):
        with session_factory() as session:
            _group(group_id, session)
            c = _controller(group_id, session)
            return {"switches": [dataclasses.asdict(r) for r in c.switch_receipts]}

    return router
