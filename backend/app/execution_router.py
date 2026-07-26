import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from redis import Redis
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.composer_router import plan_to_dict
from app.config import get_settings
from app.db import get_db
from app.endpoint_router import current_user
from app.execution_capabilities import CAPABILITY_PACK, IMPLEMENTED_METHODS
from app.models import TunnelPlan, TunnelPlanItem, User, UserRole

router = APIRouter(prefix="/api/v1")
settings = get_settings()
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def _plan_access(db: Session, user: User, plan_id: int) -> TunnelPlan:
    plan = db.get(TunnelPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="TUNNEL_PLAN_NOT_FOUND")
    if (
        user.role not in {UserRole.ADMIN, UserRole.SUPER_ADMIN}
        and plan.owner_user_id != user.id
    ):
        raise HTTPException(status_code=403, detail="TUNNEL_PLAN_ACCESS_DENIED")
    return plan


def _json(value):
    try:
        return json.loads(value or "{}")
    except Exception:
        return {}


def _iso(value):
    return value.isoformat() if value else None


def _run_to_dict(db: Session, run_id: int):
    run = db.execute(
        text("SELECT * FROM tunnel_plan_runs WHERE id=:run_id"),
        {"run_id": run_id},
    ).mappings().first()
    if run is None:
        return None

    items = db.execute(
        text(
            """
            SELECT *
            FROM tunnel_plan_run_items
            WHERE run_id=:run_id
            ORDER BY order_index ASC
            """
        ),
        {"run_id": run_id},
    ).mappings().all()

    events = db.execute(
        text(
            """
            SELECT *
            FROM tunnel_plan_run_events
            WHERE run_id=:run_id
            ORDER BY id ASC
            LIMIT 1000
            """
        ),
        {"run_id": run_id},
    ).mappings().all()

    return {
        **dict(run),
        "created_at": _iso(run["created_at"]),
        "started_at": _iso(run["started_at"]),
        "finished_at": _iso(run["finished_at"]),
        "items": [
            {
                **dict(item),
                "artifact": _json(item["artifact_json"]),
                "artifact_json": None,
                "started_at": _iso(item["started_at"]),
                "finished_at": _iso(item["finished_at"]),
            }
            for item in items
        ],
        "events": [
            {
                **dict(event),
                "details": _json(event["details_json"]),
                "details_json": None,
                "created_at": _iso(event["created_at"]),
            }
            for event in events
        ],
    }


@router.get("/tunnel-execution/capabilities")
def capabilities(user: User = Depends(current_user)):
    return {
        "pack": CAPABILITY_PACK,
        "execution_mode": "SEQUENTIAL",
        "implemented_methods": sorted(IMPLEMENTED_METHODS),
    }


@router.get("/tunnel-plans/{plan_id}/detail")
def plan_detail(
    plan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    plan = _plan_access(db, user, plan_id)
    result = plan_to_dict(db, plan)
    unsupported = sorted(
        {
            item["method_id"]
            for item in result["items"]
            if item["method_id"] not in IMPLEMENTED_METHODS
        }
    )
    latest_run_id = db.execute(
        text(
            """
            SELECT id
            FROM tunnel_plan_runs
            WHERE plan_id=:plan_id
            ORDER BY id DESC
            LIMIT 1
            """
        ),
        {"plan_id": plan.id},
    ).scalar_one_or_none()

    result.update(
        {
            "supported_for_execution": bool(result["items"]) and not unsupported,
            "unsupported_methods": unsupported,
            "capability_pack": CAPABILITY_PACK,
            "latest_run": _run_to_dict(db, latest_run_id) if latest_run_id else None,
        }
    )
    return result


@router.post("/tunnel-plans/{plan_id}/execute")
def execute_plan(
    plan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    plan = _plan_access(db, user, plan_id)

    active = db.execute(
        text(
            """
            SELECT id,status
            FROM tunnel_plan_runs
            WHERE plan_id=:plan_id
              AND status IN ('QUEUED','RUNNING','CANCEL_REQUESTED','ROLLING_BACK')
            ORDER BY id DESC
            LIMIT 1
            """
        ),
        {"plan_id": plan.id},
    ).mappings().first()
    if active:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "PLAN_ALREADY_RUNNING",
                "run_id": active["id"],
                "status": active["status"],
            },
        )

    items = db.scalars(
        select(TunnelPlanItem)
        .where(TunnelPlanItem.plan_id == plan.id)
        .order_by(TunnelPlanItem.order_index.asc())
    ).all()
    if not items:
        raise HTTPException(status_code=409, detail="TUNNEL_PLAN_IS_EMPTY")

    unsupported = sorted(
        {item.method_id for item in items if item.method_id not in IMPLEMENTED_METHODS}
    )
    if unsupported:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "EXECUTOR_NOT_READY_FOR_METHODS",
                "methods": unsupported,
                "implemented_methods": sorted(IMPLEMENTED_METHODS),
                "capability_pack": CAPABILITY_PACK,
            },
        )

    run_id = db.execute(
        text(
            """
            INSERT INTO tunnel_plan_runs (
                plan_id,owner_user_id,status,current_order,total_items,
                stop_policy,rollback_policy
            ) VALUES (
                :plan_id,:owner_user_id,'QUEUED',0,:total_items,
                :stop_policy,:rollback_policy
            )
            RETURNING id
            """
        ),
        {
            "plan_id": plan.id,
            "owner_user_id": plan.owner_user_id,
            "total_items": len(items),
            "stop_policy": plan.stop_policy,
            "rollback_policy": plan.rollback_policy,
        },
    ).scalar_one()

    for item in items:
        db.execute(
            text(
                """
                INSERT INTO tunnel_plan_run_items (
                    run_id,plan_item_id,order_index,method_id,item_name,status
                ) VALUES (
                    :run_id,:plan_item_id,:order_index,:method_id,:item_name,'WAITING'
                )
                """
            ),
            {
                "run_id": run_id,
                "plan_item_id": item.id,
                "order_index": item.order_index,
                "method_id": item.method_id,
                "item_name": item.item_name,
            },
        )
        item.status = "WAITING"
        item.last_error = None

    db.execute(
        text(
            """
            INSERT INTO tunnel_plan_run_events (
                run_id,level,message,details_json
            ) VALUES (
                :run_id,'INFO','Plan added to the sequential execution queue.',:details
            )
            """
        ),
        {
            "run_id": run_id,
            "details": json.dumps(
                {"capability_pack": CAPABILITY_PACK, "total_items": len(items)}
            ),
        },
    )

    plan.status = "QUEUED"
    plan.current_order = 0
    plan.updated_at = datetime.utcnow()
    db.commit()

    try:
        redis_client.rpush("netauto:tunnel-runs", str(run_id))
    except Exception as exc:
        db.execute(
            text(
                """
                UPDATE tunnel_plan_runs
                SET status='FAILED',error_message=:error,finished_at=CURRENT_TIMESTAMP
                WHERE id=:run_id
                """
            ),
            {"run_id": run_id, "error": "EXECUTION_QUEUE_UNAVAILABLE"},
        )
        plan.status = "FAILED"
        db.commit()
        raise HTTPException(
            status_code=503, detail="EXECUTION_QUEUE_UNAVAILABLE"
        ) from exc

    return {
        "status": "queued",
        "run_id": run_id,
        "plan_id": plan.id,
        "execution_mode": "SEQUENTIAL",
        "total_items": len(items),
        "capability_pack": CAPABILITY_PACK,
    }


@router.get("/tunnel-plans/{plan_id}/runs/latest")
def latest_run(
    plan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _plan_access(db, user, plan_id)
    run_id = db.execute(
        text(
            """
            SELECT id
            FROM tunnel_plan_runs
            WHERE plan_id=:plan_id
            ORDER BY id DESC
            LIMIT 1
            """
        ),
        {"plan_id": plan_id},
    ).scalar_one_or_none()
    if run_id is None:
        raise HTTPException(status_code=404, detail="PLAN_RUN_NOT_FOUND")
    return _run_to_dict(db, run_id)


@router.get("/tunnel-plan-runs/{run_id}")
def read_run(
    run_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    run = _run_to_dict(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="PLAN_RUN_NOT_FOUND")
    _plan_access(db, user, run["plan_id"])
    return run


@router.post("/tunnel-plan-runs/{run_id}/cancel")
def cancel_run(
    run_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    run = _run_to_dict(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="PLAN_RUN_NOT_FOUND")
    plan = _plan_access(db, user, run["plan_id"])
    if run["status"] not in {"QUEUED", "RUNNING"}:
        raise HTTPException(status_code=409, detail="RUN_IS_NOT_CANCELLABLE")

    new_status = "CANCELLED" if run["status"] == "QUEUED" else "CANCEL_REQUESTED"
    db.execute(
        text(
            """
            UPDATE tunnel_plan_runs
            SET status=:status,
                finished_at=CASE WHEN :status='CANCELLED' THEN CURRENT_TIMESTAMP ELSE finished_at END
            WHERE id=:run_id
            """
        ),
        {"run_id": run_id, "status": new_status},
    )
    db.execute(
        text(
            """
            INSERT INTO tunnel_plan_run_events (run_id,level,message)
            VALUES (:run_id,'WARNING',:message)
            """
        ),
        {
            "run_id": run_id,
            "message": "Cancellation requested."
            if new_status == "CANCEL_REQUESTED"
            else "Queued run cancelled.",
        },
    )
    if new_status == "CANCELLED":
        plan.status = "DRAFT"
    db.commit()
    return {"status": new_status, "run_id": run_id}
