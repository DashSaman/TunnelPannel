import ipaddress
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.endpoint_router import current_user, get_accessible_endpoint
from app.models import (
    Endpoint,
    NetworkInventory,
    PairPrecheck,
    TunnelPlan,
    TunnelPlanItem,
    User,
    UserRole,
)
from app.schemas import TunnelPlanCreateRequest
from app.tunnel_catalog import CATALOG, METHODS

router = APIRouter(prefix="/api/v1")

TOPOLOGIES = {"PAIR", "HUB_SPOKE", "CUSTOM"}
STOP_POLICIES = {"STOP_ON_ERROR", "CONTINUE_ON_ERROR"}
ROLLBACK_POLICIES = {"NONE", "FAILED_ITEM_ONLY", "WHOLE_PLAN"}
DIRECTIONS = {"A_TO_B", "B_TO_A", "BIDIRECTIONAL"}
INITIATORS = {"AUTO", "A", "B"}


def latest_precheck(db: Session, endpoint_a_id: int, endpoint_b_id: int):
    return db.scalar(
        select(PairPrecheck)
        .where(
            or_(
                (
                    PairPrecheck.endpoint_a_id == endpoint_a_id
                )
                & (
                    PairPrecheck.endpoint_b_id == endpoint_b_id
                ),
                (
                    PairPrecheck.endpoint_a_id == endpoint_b_id
                )
                & (
                    PairPrecheck.endpoint_b_id == endpoint_a_id
                ),
            )
        )
        .order_by(PairPrecheck.id.desc())
        .limit(1)
    )


def recommendation(db: Session, endpoint_a_id: int, endpoint_b_id: int):
    record = latest_precheck(db, endpoint_a_id, endpoint_b_id)

    if record is None:
        return {
            "code": "PRECHECK_RECOMMENDED",
            "message": "Run bidirectional precheck before execution.",
        }

    try:
        connectivity = json.loads(
            record.result_json or "{}"
        ).get("connectivity")
    except Exception:
        connectivity = None

    if connectivity == "BIDIRECTIONAL":
        return {
            "code": connectivity,
            "message": (
                "Both directions are reachable. Forward, reverse "
                "and bidirectional methods remain selectable."
            ),
        }

    if connectivity in {"A_TO_B_ONLY", "B_TO_A_ONLY"}:
        return {
            "code": connectivity,
            "message": (
                "Only one direction is reachable. A reverse or outgoing "
                "method should be initiated from the reachable side."
            ),
        }

    return {
        "code": connectivity or "NO_DIRECT_REACHABILITY",
        "message": (
            "Direct reachability is unavailable. "
            "Use reverse, relay or carrier-based methods."
        ),
    }


def load_inventory(db: Session, endpoint_id: int) -> dict:
    record = db.scalar(
        select(NetworkInventory).where(
            NetworkInventory.endpoint_id == endpoint_id
        )
    )

    if record is None or record.status != "READY":
        return {}

    try:
        return json.loads(record.inventory_json or "{}")
    except Exception:
        return {}


def normalize_address(item: dict) -> dict | None:
    value = item.get("address") or item.get("local")

    if not value:
        return None

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None

    if address.is_loopback:
        return None

    cidr = item.get("cidr")

    if not cidr and item.get("prefix") is not None:
        cidr = f"{address}/{item['prefix']}"

    return {
        "address": str(address),
        "cidr": cidr or str(address),
        "interface": item.get("interface") or item.get("ifname") or "-",
        "family": address.version,
        "scope": item.get("scope"),
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_link_local": address.is_link_local,
    }


def endpoint_addresses(db: Session, endpoint: Endpoint) -> list[dict]:
    inventory = load_inventory(db, endpoint.id)
    result = []
    seen = set()

    for item in inventory.get("addresses", []):
        normalized = normalize_address(item)

        if normalized is None:
            continue

        key = (normalized["address"], normalized["interface"])

        if key in seen:
            continue

        seen.add(key)
        result.append(normalized)

    try:
        host_ip = ipaddress.ip_address(endpoint.host)
    except ValueError:
        host_ip = None

    if (
        host_ip is not None
        and not host_ip.is_loopback
        and not any(
            item["address"] == str(host_ip)
            for item in result
        )
    ):
        result.append(
            {
                "address": str(host_ip),
                "cidr": str(host_ip),
                "interface": "endpoint-host",
                "family": host_ip.version,
                "scope": "host",
                "is_global": host_ip.is_global,
                "is_private": host_ip.is_private,
                "is_link_local": host_ip.is_link_local,
            }
        )

    result.sort(
        key=lambda item: (
            not item["is_global"],
            item["is_link_local"],
            item["family"],
            item["interface"],
            item["address"],
        )
    )

    return result


def selected_source_ip(addresses: list[dict], family: int) -> str | None:
    candidates = [
        item
        for item in addresses
        if item["family"] == family
        and not item["is_link_local"]
    ]

    global_items = [
        item
        for item in candidates
        if item["is_global"]
    ]

    if global_items:
        return global_items[0]["address"]

    if candidates:
        return candidates[0]["address"]

    return None


def existing_networks(db: Session, endpoint_ids: set[int]) -> list:
    networks = []

    records = db.scalars(
        select(NetworkInventory).where(
            NetworkInventory.endpoint_id.in_(endpoint_ids)
        )
    ).all()

    for record in records:
        try:
            data = json.loads(record.inventory_json or "{}")
        except Exception:
            continue

        for value in data.get("resources", {}).get("cidrs", []):
            try:
                networks.append(
                    ipaddress.ip_network(value, strict=False)
                )
            except ValueError:
                pass

    for item in db.scalars(select(TunnelPlanItem)).all():
        try:
            config = json.loads(item.config_json or "{}")
        except Exception:
            continue

        for key in {
            "tunnel_cidr",
            "subnet",
            "inner_subnet",
            "outer_subnet",
            "ipv6_subnet",
        }:
            value = config.get(key)

            if not value:
                continue

            try:
                networks.append(
                    ipaddress.ip_network(value, strict=False)
                )
            except ValueError:
                pass

    return networks


def free_networks(used: list, family: int, count: int) -> list:
    if family == 6:
        pools = [
            ipaddress.ip_network("fd77:77::/112"),
            ipaddress.ip_network("fd78:78::/112"),
        ]
        prefix = 126
    else:
        pools = [
            ipaddress.ip_network("10.77.0.0/16"),
            ipaddress.ip_network("10.78.0.0/16"),
            ipaddress.ip_network("172.27.0.0/16"),
        ]
        prefix = 30

    result = []

    for pool in pools:
        for candidate in pool.subnets(new_prefix=prefix):
            if any(
                existing.version == candidate.version
                and existing.overlaps(candidate)
                for existing in used
            ):
                continue

            hosts = list(candidate.hosts())

            if len(hosts) < 2:
                continue

            result.append(
                {
                    "tunnel_cidr": str(candidate),
                    "tunnel_ip_a": (
                        f"{hosts[0]}/{candidate.prefixlen}"
                    ),
                    "tunnel_ip_b": (
                        f"{hosts[1]}/{candidate.prefixlen}"
                    ),
                }
            )

            used.append(candidate)

            if len(result) >= count:
                return result

    return result


def validate_source_ip(
    db: Session,
    endpoint: Endpoint,
    value: str | None,
    order_index: int,
    side: str,
):
    if not value:
        return

    try:
        requested = ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_SOURCE_IP",
                "side": side,
                "order": order_index,
                "value": value,
            },
        ) from exc

    addresses = endpoint_addresses(db, endpoint)

    if (
        addresses
        and str(requested)
        not in {
            item["address"]
            for item in addresses
        }
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SOURCE_IP_NOT_FOUND_ON_ENDPOINT",
                "side": side,
                "order": order_index,
                "value": str(requested),
                "endpoint_id": endpoint.id,
            },
        )


def validate_internal_addressing(
    config: dict,
    order_index: int,
    reserved: list,
):
    cidr_value = config.get("tunnel_cidr")
    ip_a_value = config.get("tunnel_ip_a")
    ip_b_value = config.get("tunnel_ip_b")

    if not any([cidr_value, ip_a_value, ip_b_value]):
        return

    if not all([cidr_value, ip_a_value, ip_b_value]):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INCOMPLETE_INTERNAL_ADDRESSING",
                "order": order_index,
            },
        )

    try:
        network = ipaddress.ip_network(cidr_value, strict=False)
        address_a = ipaddress.ip_interface(ip_a_value)
        address_b = ipaddress.ip_interface(ip_b_value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_INTERNAL_ADDRESSING",
                "order": order_index,
            },
        ) from exc

    if address_a.ip not in network or address_b.ip not in network:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "TUNNEL_IP_OUTSIDE_CIDR",
                "order": order_index,
            },
        )

    if address_a.ip == address_b.ip:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "DUPLICATE_TUNNEL_IP",
                "order": order_index,
            },
        )

    conflict = next(
        (
            existing
            for existing in reserved
            if existing.version == network.version
            and existing.overlaps(network)
        ),
        None,
    )

    if conflict is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "TUNNEL_CIDR_CONFLICT",
                "order": order_index,
                "requested": str(network),
                "existing": str(conflict),
            },
        )

    reserved.append(network)


def validate_plan(
    db: Session,
    user: User,
    payload: TunnelPlanCreateRequest,
):
    if payload.topology not in TOPOLOGIES:
        raise HTTPException(400, "INVALID_TOPOLOGY")

    if payload.stop_policy not in STOP_POLICIES:
        raise HTTPException(400, "INVALID_STOP_POLICY")

    if payload.rollback_policy not in ROLLBACK_POLICIES:
        raise HTTPException(400, "INVALID_ROLLBACK_POLICY")

    endpoint_ids = {
        item.endpoint_a_id
        for item in payload.items
    } | {
        item.endpoint_b_id
        for item in payload.items
    }

    reserved_networks = existing_networks(db, endpoint_ids)
    signatures = set()
    recommendations = {}
    result_items = []

    for order_index, item in enumerate(payload.items, start=1):
        if item.endpoint_a_id == item.endpoint_b_id:
            raise HTTPException(
                400,
                {
                    "code": "SAME_ENDPOINT",
                    "order": order_index,
                },
            )

        endpoint_a = get_accessible_endpoint(
            db, user, item.endpoint_a_id
        )
        endpoint_b = get_accessible_endpoint(
            db, user, item.endpoint_b_id
        )

        if endpoint_a.status != "READY" or endpoint_b.status != "READY":
            raise HTTPException(
                409,
                {
                    "code": "ENDPOINT_NOT_READY",
                    "order": order_index,
                },
            )

        method = METHODS.get(item.method_id)

        if method is None:
            raise HTTPException(
                400,
                {
                    "code": "UNKNOWN_METHOD",
                    "method": item.method_id,
                },
            )

        if (
            item.traffic_direction not in DIRECTIONS
            or item.traffic_direction not in method["directions"]
        ):
            raise HTTPException(
                400,
                {
                    "code": "INVALID_DIRECTION",
                    "order": order_index,
                },
            )

        if item.initiator not in INITIATORS:
            raise HTTPException(
                400,
                {
                    "code": "INVALID_INITIATOR",
                    "order": order_index,
                },
            )

        if (
            item.carrier_method_id
            and item.carrier_method_id not in method["carriers"]
        ):
            raise HTTPException(
                400,
                {
                    "code": "INCOMPATIBLE_CARRIER",
                    "order": order_index,
                },
            )

        config = dict(item.config or {})

        validate_source_ip(
            db,
            endpoint_a,
            config.get("source_ip_a"),
            order_index,
            "A",
        )
        validate_source_ip(
            db,
            endpoint_b,
            config.get("source_ip_b"),
            order_index,
            "B",
        )
        validate_internal_addressing(
            config,
            order_index,
            reserved_networks,
        )

        signature = (
            item.endpoint_a_id,
            item.endpoint_b_id,
            item.item_name,
            item.method_id,
            item.carrier_method_id,
            item.traffic_direction,
            item.initiator,
            json.dumps(config, sort_keys=True),
        )

        if signature in signatures:
            raise HTTPException(
                409,
                {
                    "code": "EXACT_DUPLICATE",
                    "order": order_index,
                },
            )

        signatures.add(signature)

        pair_key = (
            f"{min(endpoint_a.id, endpoint_b.id)}:"
            f"{max(endpoint_a.id, endpoint_b.id)}"
        )

        recommendations.setdefault(
            pair_key,
            recommendation(db, endpoint_a.id, endpoint_b.id),
        )

        result_items.append(
            {
                "order_index": order_index,
                "endpoint_a": {
                    "id": endpoint_a.id,
                    "name": endpoint_a.name,
                    "host": endpoint_a.host,
                },
                "endpoint_b": {
                    "id": endpoint_b.id,
                    "name": endpoint_b.name,
                    "host": endpoint_b.host,
                },
                "item_name": item.item_name,
                "method": method,
                "carrier": (
                    METHODS.get(item.carrier_method_id)
                    if item.carrier_method_id
                    else None
                ),
                "traffic_direction": item.traffic_direction,
                "initiator": item.initiator,
                "config": config,
                "status": "WAITING",
            }
        )

    return {
        "name": payload.name,
        "topology": payload.topology,
        "execution_mode": "SEQUENTIAL",
        "stop_policy": payload.stop_policy,
        "rollback_policy": payload.rollback_policy,
        "total_items": len(result_items),
        "items": result_items,
        "recommendations": recommendations,
    }


def plan_to_dict(db: Session, plan: TunnelPlan):
    rows = db.scalars(
        select(TunnelPlanItem)
        .where(TunnelPlanItem.plan_id == plan.id)
        .order_by(TunnelPlanItem.order_index)
    ).all()

    endpoint_ids = {
        row.endpoint_a_id
        for row in rows
    } | {
        row.endpoint_b_id
        for row in rows
    }

    endpoints = (
        {
            endpoint.id: endpoint
            for endpoint in db.scalars(
                select(Endpoint).where(
                    Endpoint.id.in_(endpoint_ids)
                )
            ).all()
        }
        if endpoint_ids
        else {}
    )

    return {
        "id": plan.id,
        "name": plan.name,
        "topology": plan.topology,
        "status": plan.status,
        "execution_mode": plan.execution_mode,
        "stop_policy": plan.stop_policy,
        "rollback_policy": plan.rollback_policy,
        "total_items": plan.total_items,
        "current_order": plan.current_order,
        "created_at": (
            plan.created_at.isoformat()
            if plan.created_at
            else None
        ),
        "items": [
            {
                "id": row.id,
                "order_index": row.order_index,
                "endpoint_a": {
                    "id": row.endpoint_a_id,
                    "name": (
                        endpoints[row.endpoint_a_id].name
                        if row.endpoint_a_id in endpoints
                        else "-"
                    ),
                },
                "endpoint_b": {
                    "id": row.endpoint_b_id,
                    "name": (
                        endpoints[row.endpoint_b_id].name
                        if row.endpoint_b_id in endpoints
                        else "-"
                    ),
                },
                "item_name": row.item_name,
                "method_id": row.method_id,
                "method_name": METHODS.get(
                    row.method_id, {}
                ).get("name", row.method_id),
                "carrier_method_id": row.carrier_method_id,
                "traffic_direction": row.traffic_direction,
                "initiator": row.initiator,
                "status": row.status,
                "config": json.loads(row.config_json or "{}"),
                "last_error": row.last_error,
            }
            for row in rows
        ],
    }


@router.get("/tunnel-catalog")
def tunnel_catalog(user: User = Depends(current_user)):
    return {
        "execution_mode": "SEQUENTIAL",
        "categories": list(
            dict.fromkeys(
                item["category"]
                for item in CATALOG
            )
        ),
        "methods": [
            dict(
                item,
                carrier_options=[
                    METHODS[carrier_id]
                    for carrier_id in item["carriers"]
                    if carrier_id in METHODS
                ],
            )
            for item in CATALOG
        ],
    }


@router.get("/tunnel-plans/addressing-suggestions")
def addressing_suggestions(
    endpoint_a_id: int = Query(gt=0),
    endpoint_b_id: int = Query(gt=0),
    family: int = Query(default=4, ge=4, le=6),
    count: int = Query(default=32, ge=1, le=200),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if family not in {4, 6}:
        raise HTTPException(400, "INVALID_IP_FAMILY")

    if endpoint_a_id == endpoint_b_id:
        raise HTTPException(400, "SAME_ENDPOINT")

    endpoint_a = get_accessible_endpoint(
        db, user, endpoint_a_id
    )
    endpoint_b = get_accessible_endpoint(
        db, user, endpoint_b_id
    )

    addresses_a = endpoint_addresses(db, endpoint_a)
    addresses_b = endpoint_addresses(db, endpoint_b)
    used = existing_networks(
        db,
        {endpoint_a.id, endpoint_b.id},
    )

    return {
        "endpoint_a": {
            "id": endpoint_a.id,
            "name": endpoint_a.name,
            "host": endpoint_a.host,
            "addresses": addresses_a,
            "suggested_source_ip": selected_source_ip(
                addresses_a, family
            ),
        },
        "endpoint_b": {
            "id": endpoint_b.id,
            "name": endpoint_b.name,
            "host": endpoint_b.host,
            "addresses": addresses_b,
            "suggested_source_ip": selected_source_ip(
                addresses_b, family
            ),
        },
        "family": family,
        "suggestions": free_networks(
            used, family, count
        ),
    }


@router.post("/tunnel-plans/preview")
def preview_tunnel_plan(
    payload: TunnelPlanCreateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return validate_plan(db, user, payload)


@router.post("/tunnel-plans")
def create_tunnel_plan(
    payload: TunnelPlanCreateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    preview = validate_plan(db, user, payload)

    plan = TunnelPlan(
        owner_user_id=user.id,
        name=payload.name.strip(),
        topology=payload.topology,
        status="DRAFT",
        execution_mode="SEQUENTIAL",
        stop_policy=payload.stop_policy,
        rollback_policy=payload.rollback_policy,
        total_items=len(preview["items"]),
        current_order=0,
        config_json=json.dumps(
            {
                "recommendations": preview["recommendations"],
            },
            ensure_ascii=False,
        ),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(plan)
    db.flush()

    for item in preview["items"]:
        db.add(
            TunnelPlanItem(
                plan_id=plan.id,
                order_index=item["order_index"],
                endpoint_a_id=item["endpoint_a"]["id"],
                endpoint_b_id=item["endpoint_b"]["id"],
                item_name=item["item_name"],
                method_id=item["method"]["id"],
                carrier_method_id=(
                    item["carrier"]["id"]
                    if item["carrier"]
                    else None
                ),
                traffic_direction=item["traffic_direction"],
                initiator=item["initiator"],
                status="WAITING",
                config_json=json.dumps(
                    item["config"],
                    ensure_ascii=False,
                ),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
        )

    db.commit()
    db.refresh(plan)

    return {
        "status": "saved",
        "plan": plan_to_dict(db, plan),
    }


@router.get("/tunnel-plans")
def list_tunnel_plans(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(TunnelPlan)

    if user.role not in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }:
        query = query.where(
            TunnelPlan.owner_user_id == user.id
        )

    plans = db.scalars(
        query.order_by(
            TunnelPlan.id.desc()
        ).limit(50)
    ).all()

    return {
        "items": [
            plan_to_dict(db, plan)
            for plan in plans
        ]
    }


@router.delete("/tunnel-plans/{plan_id}")
def delete_tunnel_plan(
    plan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    plan = db.get(TunnelPlan, plan_id)

    if plan is None:
        raise HTTPException(
            404,
            "TUNNEL_PLAN_NOT_FOUND",
        )

    if (
        user.role not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and plan.owner_user_id != user.id
    ):
        raise HTTPException(
            403,
            "TUNNEL_PLAN_ACCESS_DENIED",
        )

    if plan.status != "DRAFT":
        raise HTTPException(
            409,
            "ONLY_DRAFT_CAN_BE_DELETED",
        )

    for item in db.scalars(
        select(TunnelPlanItem).where(
            TunnelPlanItem.plan_id == plan.id
        )
    ).all():
        db.delete(item)

    db.delete(plan)
    db.commit()

    return {
        "status": "deleted",
        "plan_id": plan_id,
    }
