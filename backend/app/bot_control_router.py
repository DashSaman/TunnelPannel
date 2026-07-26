import copy
import json
import re
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from app.composer_router import (
    create_tunnel_plan,
    delete_tunnel_plan,
    endpoint_addresses,
    existing_networks,
    free_networks,
    plan_to_dict,
    selected_source_ip,
)
from app.db import get_db
from app.endpoint_router import (
    create_pair_precheck,
    linked_telegram_user,
    read_bot_job,
    require_bot_key,
)
from app.execution_capabilities import CAPABILITY_PACK, IMPLEMENTED_METHODS
from app.execution_router import _run_to_dict, cancel_run, execute_plan
from app.models import (
    Endpoint,
    Job,
    NetworkInventory,
    PairPrecheck,
    TelegramProfile,
    TunnelPlan,
    TunnelPlanItem,
    User,
    UserRole,
)
from app.schemas import (
    PairPrecheckCreateRequest,
    TunnelPlanCreateRequest,
    TunnelPlanItemInput,
)
from app.tunnel_catalog import CATALOG, METHODS

router = APIRouter(
    prefix="/api/v1/bot-control",
    tags=["telegram-control"],
    dependencies=[Depends(require_bot_key)],
)

SUPPORTED_LANGUAGES = {"en", "fa", "ru", "zh-CN", "de"}
ADMIN_ROLES = {UserRole.ADMIN, UserRole.SUPER_ADMIN}
ACTIVE_RUNS = {"QUEUED", "RUNNING", "CANCEL_REQUESTED", "ROLLING_BACK"}
TERMINAL_RUNS = {"SUCCESS", "FAILED", "WARNING", "CANCELLED", "ROLLED_BACK"}

ADDRESSING_METHODS = {
    "GRE", "GRETAP", "IPIP", "SIT_6IN4", "IP6GRE", "IP6GRETAP",
    "VXLAN", "WIREGUARD", "SSH_TUN_L3", "SSH_TAP_L2", "GOST_TUN",
    "GOST_TAP", "OPENVPN", "IKEV2_IPSEC", "L2TP_IPSEC", "VTI", "VTI6",
    "SIT_OVER_GOST", "GRE_OVER_GOST", "GRETAP_OVER_GOST", "SIT_OVER_SSH",
    "GRE_OVER_SSH", "GRE_OVER_WIREGUARD",
}
OUTER_IPV6 = {"IP6GRE", "IP6GRETAP", "VTI6"}
INNER_IPV6 = {"SIT_6IN4", "SIT_OVER_GOST", "SIT_OVER_SSH"}
FORWARD_METHODS = {
    "SSH_LOCAL_FORWARD", "SSH_REMOTE_FORWARD", "AUTOSSH_REVERSE",
    "GOST_TCP_FORWARD", "GOST_UDP_FORWARD", "GOST_REMOTE_TCP",
    "GOST_REMOTE_UDP", "GOST_KCP_FORWARD", "FRP_TCP", "FRP_UDP",
    "FRP_STCP", "FRP_XTCP", "FRP_KCP", "FRP_QUIC", "RATHOLE_TCP",
    "RATHOLE_UDP", "RATHOLE_TLS", "RATHOLE_NOISE", "RATHOLE_WEBSOCKET",
    "CHISEL_TCP", "CHISEL_UDP", "CHISEL_REVERSE_TCP",
    "CHISEL_REVERSE_UDP", "WSTUNNEL_TCP", "WSTUNNEL_UDP",
    "WATERWALL_DIRECT", "WATERWALL_REVERSE", "WATERWALL_TLS_MUX",
    "PAQET_RAW_KCP",
}
PROXY_METHODS = {
    "SSH_DYNAMIC_SOCKS", "GOST_SOCKS5", "GOST_SOCKS5_KCP",
    "CHISEL_SOCKS5", "CHISEL_REVERSE_SOCKS5", "WSTUNNEL_SOCKS5",
    "PAQET_SOCKS5", "VLESS_TCP", "VLESS_WS", "VLESS_GRPC",
    "VLESS_XHTTP", "VLESS_REALITY", "VLESS_VISION_REALITY",
    "VLESS_XHTTP_REALITY", "HYSTERIA2", "TUIC", "TROJAN_TLS",
    "SHADOWSOCKS",
}
SAFE_ARTIFACT_KEYS = {
    "method", "interface_name", "systemd_unit", "tunnel_cidr",
    "tunnel_ip_a", "tunnel_ip_b", "source_ip_a", "source_ip_b",
    "listen_port", "listen_port_a", "listen_port_b", "relay_port",
    "transport", "encrypted", "mtu", "vxlan_vni", "vxlan_port",
    "client_side", "server_side", "warning", "benchmark",
    "stability_score", "recommendation", "resilience",
}
SAFE_CONFIG_KEYS = {
    "mode", "tunnel_cidr", "tunnel_ip_a", "tunnel_ip_b", "source_ip_a",
    "source_ip_b", "mtu", "target_host", "target_port", "listen_host",
    "listen_port", "bind_address", "transport_port", "kcp_mode",
    "connections", "benchmark_enabled", "benchmark_duration",
    "benchmark_max_mbps", "route_cidrs",
}


class LanguageRequest(BaseModel):
    telegram_id: int
    username: str | None = Field(default=None, max_length=100)
    language: str = Field(max_length=10)


class SimplePlanRequest(BaseModel):
    telegram_id: int
    name: str = Field(min_length=2, max_length=180)
    endpoint_a_id: int = Field(gt=0)
    endpoint_b_id: int = Field(gt=0)
    method_id: str = Field(min_length=2, max_length=100)
    traffic_direction: str | None = Field(default=None, max_length=30)
    initiator: str | None = Field(default=None, max_length=20)
    target_port: int = Field(default=22, ge=1, le=65535)
    stop_policy: str = Field(default="STOP_ON_ERROR", max_length=30)
    rollback_policy: str = Field(default="FAILED_ITEM_ONLY", max_length=40)


class BotPrecheckRequest(BaseModel):
    telegram_id: int
    endpoint_a_id: int = Field(gt=0)
    endpoint_b_id: int = Field(gt=0)


def _iso(value):
    return value.isoformat() if value else None


def _json(value, fallback=None):
    fallback = {} if fallback is None else fallback
    try:
        return json.loads(value or "{}")
    except Exception:
        return fallback


def _access_query(user, model):
    query = select(model)
    if user.role not in ADMIN_ROLES:
        query = query.where(model.owner_user_id == user.id)
    return query


def _accessible_endpoint(db: Session, user, endpoint_id: int) -> Endpoint:
    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(404, "ENDPOINT_NOT_FOUND")
    if user.role not in ADMIN_ROLES and endpoint.owner_user_id != user.id:
        raise HTTPException(403, "ENDPOINT_ACCESS_DENIED")
    return endpoint


def _accessible_plan(db: Session, user, plan_id: int) -> TunnelPlan:
    plan = db.get(TunnelPlan, plan_id)
    if plan is None:
        raise HTTPException(404, "TUNNEL_PLAN_NOT_FOUND")
    if user.role not in ADMIN_ROLES and plan.owner_user_id != user.id:
        raise HTTPException(403, "TUNNEL_PLAN_ACCESS_DENIED")
    return plan


def _endpoint_dict(endpoint: Endpoint, inventory: NetworkInventory | None = None):
    result = {
        "id": endpoint.id,
        "name": endpoint.name,
        "host": endpoint.host,
        "port": endpoint.port,
        "device_type": endpoint.device_type,
        "status": endpoint.status,
        "display_location": endpoint.display_location,
        "detected_os": endpoint.detected_os,
        "detected_version": endpoint.detected_version,
        "detected_arch": endpoint.detected_arch,
        "detected_hostname": endpoint.detected_hostname,
        "primary_interface": endpoint.primary_interface,
        "public_ip": endpoint.public_ip,
        "last_error": endpoint.last_error,
        "created_at": _iso(endpoint.created_at),
        "updated_at": _iso(endpoint.updated_at),
    }
    result["inventory"] = {
        "status": inventory.status if inventory else "NOT_SCANNED",
        "summary": _json(inventory.summary_json) if inventory else {},
        "scanned_at": _iso(inventory.scanned_at) if inventory else None,
        "last_error": inventory.last_error if inventory else None,
    }
    return result


def _redact(value: Any, limit: int = 1500) -> str | None:
    if value is None:
        return None
    text_value = str(value)
    patterns = [
        (r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]"),
        (r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----", "[PRIVATE KEY REDACTED]"),
        (r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]"),
    ]
    for pattern, replacement in patterns:
        text_value = re.sub(pattern, replacement, text_value, flags=re.S)
    return text_value[:limit]


def _safe_artifact(value: Any):
    artifact = value if isinstance(value, dict) else {}
    return {key: artifact[key] for key in SAFE_ARTIFACT_KEYS if key in artifact}


def _safe_run(run: dict | None):
    if not run:
        return None
    return {
        "id": run["id"],
        "plan_id": run["plan_id"],
        "status": run["status"],
        "current_order": run.get("current_order"),
        "total_items": run.get("total_items"),
        "stop_policy": run.get("stop_policy"),
        "rollback_policy": run.get("rollback_policy"),
        "error_message": _redact(run.get("error_message")),
        "created_at": run.get("created_at"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "items": [
            {
                "id": item["id"],
                "order_index": item["order_index"],
                "method_id": item["method_id"],
                "item_name": item["item_name"],
                "status": item["status"],
                "error_message": _redact(item.get("error_message")),
                "started_at": item.get("started_at"),
                "finished_at": item.get("finished_at"),
                "artifact": _safe_artifact(item.get("artifact")),
            }
            for item in run.get("items", [])
        ],
        "events": [
            {
                "id": event["id"],
                "run_item_id": event.get("run_item_id"),
                "level": event["level"],
                "message": _redact(event["message"], 700),
                "created_at": event["created_at"],
            }
            for event in run.get("events", [])[-100:]
        ],
    }


def _safe_plan(db: Session, plan: TunnelPlan):
    data = plan_to_dict(db, plan)
    for item in data.get("items", []):
        config = item.get("config") or {}
        item["config"] = {key: config[key] for key in SAFE_CONFIG_KEYS if key in config}
    return data


def _latest_run_id(db: Session, plan_id: int):
    return db.execute(
        text(
            """
            SELECT id FROM tunnel_plan_runs
            WHERE plan_id=:plan_id
            ORDER BY id DESC LIMIT 1
            """
        ),
        {"plan_id": plan_id},
    ).scalar_one_or_none()


def _readiness(db: Session, plan: TunnelPlan):
    items = db.scalars(
        select(TunnelPlanItem)
        .where(TunnelPlanItem.plan_id == plan.id)
        .order_by(TunnelPlanItem.order_index.asc())
    ).all()
    endpoint_ids = {item.endpoint_a_id for item in items} | {
        item.endpoint_b_id for item in items
    }
    missing_inventory, stale_inventory = [], []
    now = datetime.utcnow()
    for endpoint_id in sorted(endpoint_ids):
        inventory = db.scalar(
            select(NetworkInventory).where(NetworkInventory.endpoint_id == endpoint_id)
        )
        if inventory is None or inventory.status != "READY":
            missing_inventory.append(endpoint_id)
        elif not inventory.scanned_at or inventory.scanned_at < now - timedelta(hours=24):
            stale_inventory.append(endpoint_id)

    pairs = {
        tuple(sorted((item.endpoint_a_id, item.endpoint_b_id))) for item in items
    }
    missing_prechecks = []
    for endpoint_a_id, endpoint_b_id in sorted(pairs):
        record = db.scalar(
            select(PairPrecheck)
            .where(
                or_(
                    (PairPrecheck.endpoint_a_id == endpoint_a_id)
                    & (PairPrecheck.endpoint_b_id == endpoint_b_id),
                    (PairPrecheck.endpoint_a_id == endpoint_b_id)
                    & (PairPrecheck.endpoint_b_id == endpoint_a_id),
                )
            )
            .order_by(PairPrecheck.id.desc())
            .limit(1)
        )
        if (
            record is None
            or record.status != "SUCCESS"
            or not record.finished_at
            or record.finished_at < now - timedelta(hours=6)
        ):
            missing_prechecks.append(
                {"endpoint_a_id": endpoint_a_id, "endpoint_b_id": endpoint_b_id}
            )
    return {
        "ready": not (missing_inventory or stale_inventory or missing_prechecks),
        "missing_inventory": missing_inventory,
        "stale_inventory": stale_inventory,
        "missing_prechecks": missing_prechecks,
    }


def _auto_config(
    db: Session,
    endpoint_a: Endpoint,
    endpoint_b: Endpoint,
    method_id: str,
    target_port: int,
):
    method = METHODS[method_id]
    defaults = copy.deepcopy(method.get("simple_defaults") or {})
    config = copy.deepcopy(defaults.get("config") or {})
    config.update(
        {
            "mode": "SIMPLE",
            "auto_allocate": True,
            "auto_install": True,
            "auto_precheck": True,
            "auto_inventory_refresh": True,
            "benchmark_enabled": True,
            "benchmark_duration": int(config.get("benchmark_duration", 6)),
            "benchmark_max_mbps": int(config.get("benchmark_max_mbps", 200)),
        }
    )
    if method_id == "SINGBOX_TUN":
        raise HTTPException(
            409,
            {"code": "ADVANCED_CONFIGURATION_REQUIRED", "method": method_id},
        )
    if method_id in FORWARD_METHODS:
        config.setdefault("target_host", "127.0.0.1")
        config.setdefault("target_port", target_port)
        config.setdefault("local_host", "127.0.0.1")
        config.setdefault("local_port", target_port)
        config.setdefault("listen_host", "127.0.0.1")
        config.setdefault("bind_address", "127.0.0.1")
    if method_id in PROXY_METHODS:
        config.setdefault("listen_host", "127.0.0.1")
        config.setdefault("bind_address", "127.0.0.1")
        config.setdefault("target_host", "127.0.0.1")
        config.setdefault("target_port", target_port)
    if method_id.startswith("PAQET_"):
        config.setdefault("kcp_mode", "fast")
        config.setdefault("connections", 1)
    if method_id == "WATERWALL_REVERSE":
        config.setdefault("minimum_unused", 8)

    if method_id not in ADDRESSING_METHODS:
        return config

    outer_family = 6 if method_id in OUTER_IPV6 else 4
    inner_family = 6 if method_id in INNER_IPV6 else 4
    addresses_a = endpoint_addresses(db, endpoint_a)
    addresses_b = endpoint_addresses(db, endpoint_b)
    source_a = selected_source_ip(addresses_a, outer_family)
    source_b = selected_source_ip(addresses_b, outer_family)
    if not source_a or not source_b:
        raise HTTPException(
            409,
            {
                "code": "SOURCE_ADDRESS_FAMILY_UNAVAILABLE",
                "family": outer_family,
                "endpoint_ids": [endpoint_a.id, endpoint_b.id],
            },
        )
    suggestions = free_networks(
        existing_networks(db, {endpoint_a.id, endpoint_b.id}), inner_family, 1
    )
    if not suggestions:
        raise HTTPException(409, "NO_FREE_TUNNEL_NETWORK")
    config.update(
        {"source_ip_a": source_a, "source_ip_b": source_b, **suggestions[0]}
    )
    config.setdefault("mtu", 1360 if inner_family == 6 else 1400)
    return config


@router.get("/context/{telegram_id}")
def context(telegram_id: int, db: Session = Depends(get_db)):
    profile = db.scalar(
        select(TelegramProfile).where(TelegramProfile.telegram_id == telegram_id)
    )
    # Do not turn an unlinked account into a 403 response.
    linked = db.scalar(select(User).where(User.telegram_id == telegram_id))
    return {
        "has_profile": profile is not None,
        "language": profile.language if profile else "en",
        "linked": linked is not None,
        "user_id": linked.id if linked else None,
        "username": linked.username if linked else None,
        "role": linked.role.value if linked else "GUEST",
        "is_active": linked.is_active if linked else False,
    }


@router.post("/language")
def set_language(payload: LanguageRequest, db: Session = Depends(get_db)):
    if payload.language not in SUPPORTED_LANGUAGES:
        raise HTTPException(400, "UNSUPPORTED_LANGUAGE")
    profile = db.scalar(
        select(TelegramProfile).where(
            TelegramProfile.telegram_id == payload.telegram_id
        )
    )
    if profile is None:
        profile = TelegramProfile(
            telegram_id=payload.telegram_id,
            username=payload.username,
            language=payload.language,
        )
        db.add(profile)
    else:
        profile.username = payload.username
        profile.language = payload.language
    db.commit()
    return {"status": "ok", "language": payload.language}


@router.get("/dashboard/{telegram_id}")
def dashboard(telegram_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    endpoints = db.scalars(_access_query(user, Endpoint)).all()
    plans = db.scalars(_access_query(user, TunnelPlan)).all()
    jobs = db.scalars(_access_query(user, Job)).all()
    query = (
        "SELECT COUNT(*) FROM tunnel_plan_runs "
        "WHERE status IN ('QUEUED','RUNNING','CANCEL_REQUESTED','ROLLING_BACK')"
    )
    params = {}
    if user.role not in ADMIN_ROLES:
        query += " AND owner_user_id=:owner_user_id"
        params["owner_user_id"] = user.id
    active_runs = db.execute(text(query), params).scalar_one()
    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role.value,
            "is_active": user.is_active,
        },
        "counts": {
            "endpoints": len(endpoints),
            "ready_endpoints": sum(item.status == "READY" for item in endpoints),
            "plans": len(plans),
            "active_jobs": sum(item.status in {"QUEUED", "RUNNING", "RETRY"} for item in jobs),
            "active_runs": active_runs,
            "methods": len(IMPLEMENTED_METHODS),
        },
        "capability_pack": CAPABILITY_PACK,
    }


@router.get("/catalog/{telegram_id}")
def catalog(telegram_id: int, db: Session = Depends(get_db)):
    linked_telegram_user(telegram_id, db)
    methods = []
    for source in CATALOG:
        item = dict(source)
        item["executable"] = item["id"] in IMPLEMENTED_METHODS
        item["carrier_options"] = [
            {"id": cid, "name": METHODS.get(cid, {}).get("name", cid)}
            for cid in item.get("carriers", [])
        ]
        methods.append(item)
    return {
        "pack": CAPABILITY_PACK,
        "execution_mode": "SEQUENTIAL",
        "implemented_count": len(IMPLEMENTED_METHODS),
        "categories": list(dict.fromkeys(item["category"] for item in methods)),
        "methods": methods,
    }


@router.get("/endpoints/{telegram_id}")
def endpoints(telegram_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    rows = db.scalars(_access_query(user, Endpoint).order_by(Endpoint.id.desc())).all()
    inventories = {
        item.endpoint_id: item
        for item in db.scalars(
            select(NetworkInventory).where(
                NetworkInventory.endpoint_id.in_([row.id for row in rows])
            )
        ).all()
    } if rows else {}
    return {"items": [_endpoint_dict(row, inventories.get(row.id)) for row in rows]}


@router.get("/plans/{telegram_id}")
def plans(telegram_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    rows = db.scalars(
        _access_query(user, TunnelPlan).order_by(TunnelPlan.id.desc()).limit(100)
    ).all()
    return {"items": [_safe_plan(db, row) for row in rows]}


@router.get("/plans/{telegram_id}/{plan_id}")
def plan_detail(telegram_id: int, plan_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    plan = _accessible_plan(db, user, plan_id)
    result = _safe_plan(db, plan)
    result["readiness"] = _readiness(db, plan)
    run_id = _latest_run_id(db, plan.id)
    result["latest_run"] = _safe_run(_run_to_dict(db, run_id)) if run_id else None
    return result


@router.post("/plans/simple")
def create_simple_plan(payload: SimplePlanRequest, db: Session = Depends(get_db)):
    user = linked_telegram_user(payload.telegram_id, db)
    if payload.endpoint_a_id == payload.endpoint_b_id:
        raise HTTPException(400, "ENDPOINTS_MUST_BE_DIFFERENT")
    endpoint_a = _accessible_endpoint(db, user, payload.endpoint_a_id)
    endpoint_b = _accessible_endpoint(db, user, payload.endpoint_b_id)
    if endpoint_a.status != "READY" or endpoint_b.status != "READY":
        raise HTTPException(409, "BOTH_ENDPOINTS_MUST_BE_READY")
    method = METHODS.get(payload.method_id)
    if method is None:
        raise HTTPException(400, "UNKNOWN_METHOD")
    if payload.method_id not in IMPLEMENTED_METHODS:
        raise HTTPException(409, "METHOD_NOT_EXECUTABLE")
    defaults = copy.deepcopy(method.get("simple_defaults") or {})
    directions = method.get("directions") or ["BIDIRECTIONAL"]
    direction = payload.traffic_direction or defaults.get("traffic_direction") or directions[0]
    if direction not in directions:
        raise HTTPException(400, "INVALID_DIRECTION")
    initiators = method.get("initiators") or ["AUTO"]
    initiator = payload.initiator or defaults.get("initiator") or "AUTO"
    if initiator not in initiators:
        initiator = initiators[0]
    carrier = defaults.get("carrier_method_id")
    if carrier and carrier not in method.get("carriers", []):
        carrier = None
    config = _auto_config(
        db, endpoint_a, endpoint_b, payload.method_id, payload.target_port
    )
    request = TunnelPlanCreateRequest(
        name=payload.name.strip(),
        topology="PAIR",
        stop_policy=payload.stop_policy,
        rollback_policy=payload.rollback_policy,
        items=[
            TunnelPlanItemInput(
                endpoint_a_id=endpoint_a.id,
                endpoint_b_id=endpoint_b.id,
                item_name=f"{method['name']} — {endpoint_a.name} ↔ {endpoint_b.name}",
                method_id=payload.method_id,
                carrier_method_id=carrier,
                traffic_direction=direction,
                initiator=initiator,
                config=config,
            )
        ],
    )
    return create_tunnel_plan(request, user=user, db=db)


@router.delete("/plans/{telegram_id}/{plan_id}")
def remove_plan(telegram_id: int, plan_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    return delete_tunnel_plan(plan_id, user=user, db=db)


@router.post("/plans/{telegram_id}/{plan_id}/execute")
def start_plan(telegram_id: int, plan_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    plan = _accessible_plan(db, user, plan_id)
    readiness = _readiness(db, plan)
    if not readiness["ready"]:
        raise HTTPException(
            409, {"code": "EXECUTION_READINESS_REQUIRED", **readiness}
        )
    return execute_plan(plan_id, user=user, db=db)


@router.get("/runs/{telegram_id}/{run_id}")
def run_detail(telegram_id: int, run_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    run = _run_to_dict(db, run_id)
    if not run:
        raise HTTPException(404, "PLAN_RUN_NOT_FOUND")
    _accessible_plan(db, user, run["plan_id"])
    return _safe_run(run)


@router.post("/runs/{telegram_id}/{run_id}/cancel")
def stop_run(telegram_id: int, run_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    return cancel_run(run_id, user=user, db=db)


@router.post("/prechecks")
def queue_precheck(payload: BotPrecheckRequest, db: Session = Depends(get_db)):
    user = linked_telegram_user(payload.telegram_id, db)
    return create_pair_precheck(
        PairPrecheckCreateRequest(
            endpoint_a_id=payload.endpoint_a_id,
            endpoint_b_id=payload.endpoint_b_id,
        ),
        user=user,
        db=db,
    )


@router.get("/prechecks/{telegram_id}")
def prechecks(telegram_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    rows = db.scalars(
        _access_query(user, PairPrecheck).order_by(PairPrecheck.id.desc()).limit(50)
    ).all()
    endpoint_ids = {row.endpoint_a_id for row in rows} | {row.endpoint_b_id for row in rows}
    endpoint_map = {
        row.id: row
        for row in db.scalars(
            select(Endpoint).where(Endpoint.id.in_(endpoint_ids))
        ).all()
    } if endpoint_ids else {}
    return {
        "items": [
            {
                "id": row.id,
                "job_id": row.job_id,
                "status": row.status,
                "endpoint_a": {
                    "id": row.endpoint_a_id,
                    "name": endpoint_map.get(row.endpoint_a_id).name if endpoint_map.get(row.endpoint_a_id) else "-",
                },
                "endpoint_b": {
                    "id": row.endpoint_b_id,
                    "name": endpoint_map.get(row.endpoint_b_id).name if endpoint_map.get(row.endpoint_b_id) else "-",
                },
                "result": _json(row.result_json),
                "created_at": _iso(row.created_at),
                "finished_at": _iso(row.finished_at),
            }
            for row in rows
        ]
    }


@router.get("/prechecks/{telegram_id}/{precheck_id}")
def precheck_detail(
    telegram_id: int, precheck_id: int, db: Session = Depends(get_db)
):
    user = linked_telegram_user(telegram_id, db)
    row = db.get(PairPrecheck, precheck_id)
    if row is None:
        raise HTTPException(404, "PRECHECK_NOT_FOUND")
    if user.role not in ADMIN_ROLES and row.owner_user_id != user.id:
        raise HTTPException(403, "PRECHECK_ACCESS_DENIED")
    return {
        "id": row.id,
        "job_id": row.job_id,
        "status": row.status,
        "result": _json(row.result_json),
        "job": read_bot_job(telegram_id, row.job_id, db),
        "created_at": _iso(row.created_at),
        "finished_at": _iso(row.finished_at),
    }


@router.get("/jobs/{telegram_id}")
def jobs(telegram_id: int, db: Session = Depends(get_db)):
    user = linked_telegram_user(telegram_id, db)
    rows = db.scalars(
        _access_query(user, Job).order_by(Job.id.desc()).limit(50)
    ).all()
    endpoint_ids = {row.endpoint_id for row in rows if row.endpoint_id}
    endpoint_map = {
        row.id: row
        for row in db.scalars(select(Endpoint).where(Endpoint.id.in_(endpoint_ids))).all()
    } if endpoint_ids else {}
    return {
        "items": [
            {
                "id": row.id,
                "job_type": row.job_type,
                "status": row.status,
                "progress": row.progress,
                "current_step": row.current_step,
                "error_message": row.error_message,
                "endpoint": {
                    "id": row.endpoint_id,
                    "name": endpoint_map.get(row.endpoint_id).name if endpoint_map.get(row.endpoint_id) else "-",
                } if row.endpoint_id else None,
                "created_at": _iso(row.created_at),
                "started_at": _iso(row.started_at),
                "finished_at": _iso(row.finished_at),
            }
            for row in rows
        ]
    }
