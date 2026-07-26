from __future__ import annotations

import json
import os
import secrets
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field
from redis import Redis
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.endpoint_router import current_user
from app.models import (
    AppSetting,
    AuditLog,
    Endpoint,
    Job,
    User,
    UserRole,
)
from app.security import hash_password

router = APIRouter(prefix="/api/v1/ops", tags=["operations"])
settings = get_settings()
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)

ADMIN_ROLES = {UserRole.ADMIN, UserRole.SUPER_ADMIN}
SUPER_ADMIN_ONLY = {UserRole.SUPER_ADMIN}
ACTIVE_JOB_STATES = {"QUEUED", "RUNNING", "RETRY"}
ACTIVE_RUN_STATES = {
    "QUEUED",
    "RUNNING",
    "CANCEL_REQUESTED",
    "ROLLING_BACK",
}

SAFE_SETTING_DEFAULTS: dict[str, Any] = {
    "brand_name": settings.app_name,
    "brand_short_name": settings.app_short_name,
    "base_url": settings.app_base_url,
    "default_language": "en",
    "terminal_retention_days": 7,
    "backup_retention_days": 14,
    "xhttp_direct_enabled": True,
    "xhttp_cdn_enabled": False,
    "xhttp_cdn_provider": "cloudflare",
    "xhttp_cdn_note": "CDN mode requires a real domain, TLS and provider-side proxy configuration.",
}

PUBLIC_SETTING_KEYS = {
    "brand_name",
    "brand_short_name",
    "base_url",
    "default_language",
    "xhttp_direct_enabled",
    "xhttp_cdn_enabled",
    "xhttp_cdn_provider",
    "xhttp_cdn_note",
}


class SettingsUpdateRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr | None = None
    password: str = Field(min_length=12, max_length=200)
    role: UserRole = UserRole.USER
    is_active: bool = True
    telegram_id: int | None = None


class UserUpdateRequest(BaseModel):
    email: EmailStr | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    telegram_id: int | None = None


class PasswordResetRequest(BaseModel):
    new_password: str | None = Field(default=None, min_length=12, max_length=200)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def redact(value: str | None) -> str | None:
    if value is None:
        return None
    result = str(value)[:4000]
    patterns = [
        (r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]"),
        (r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----", "[PRIVATE KEY REDACTED]"),
        (r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]"),
    ]
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.S)
    return result


def require_admin(user: User) -> None:
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="ADMIN_REQUIRED")


def require_super_admin(user: User) -> None:
    if user.role not in SUPER_ADMIN_ONLY:
        raise HTTPException(status_code=403, detail="SUPER_ADMIN_REQUIRED")


def audit(
    db: Session,
    user: User,
    action: str,
    target_type: str,
    target_id: str | None,
    details: dict[str, Any] | str | None = None,
) -> None:
    if isinstance(details, dict):
        details_value = json.dumps(details, ensure_ascii=False)
    else:
        details_value = details

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details_value,
            created_at=utcnow(),
        )
    )


def setting_values(db: Session) -> dict[str, Any]:
    result = dict(SAFE_SETTING_DEFAULTS)

    for row in db.scalars(select(AppSetting)).all():
        if row.key not in SAFE_SETTING_DEFAULTS:
            continue
        try:
            result[row.key] = json.loads(row.value_json)
        except Exception:
            result[row.key] = SAFE_SETTING_DEFAULTS[row.key]

    return result


def serialize_user(row: User) -> dict[str, Any]:
    return {
        "id": row.id,
        "username": row.username,
        "email": row.email,
        "role": row.role.value,
        "is_active": row.is_active,
        "email_verified": row.email_verified,
        "telegram_id": row.telegram_id,
        "telegram_2fa_required": row.telegram_2fa_required,
        "must_change_password": row.must_change_password,
        "created_at": iso(row.created_at),
    }


def ensure_last_super_admin(
    db: Session,
    target: User,
    *,
    new_role: UserRole | None = None,
    new_active: bool | None = None,
) -> None:
    removes_super_admin = (
        target.role == UserRole.SUPER_ADMIN
        and (
            (new_role is not None and new_role != UserRole.SUPER_ADMIN)
            or new_active is False
        )
    )

    if not removes_super_admin:
        return

    active_count = db.scalar(
        select(func.count(User.id)).where(
            User.role == UserRole.SUPER_ADMIN,
            User.is_active.is_(True),
        )
    ) or 0

    if active_count <= 1:
        raise HTTPException(status_code=409, detail="LAST_SUPER_ADMIN_PROTECTED")


@router.get("/overview")
def overview(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    admin = user.role in ADMIN_ROLES
    owner_filter = "" if admin else " WHERE owner_user_id = :owner_id"
    params = {} if admin else {"owner_id": user.id}

    endpoint_counts = db.execute(
        text(
            "SELECT COUNT(*) AS total, "
            "COUNT(*) FILTER (WHERE status='READY') AS ready, "
            "COUNT(*) FILTER (WHERE status='ERROR') AS error "
            f"FROM endpoints{owner_filter}"
        ),
        params,
    ).mappings().one()

    job_counts = db.execute(
        text(
            "SELECT COUNT(*) AS total, "
            "COUNT(*) FILTER (WHERE status IN ('QUEUED','RUNNING','RETRY')) AS active, "
            "COUNT(*) FILTER (WHERE status='FAILED') AS failed "
            f"FROM jobs{owner_filter}"
        ),
        params,
    ).mappings().one()

    plan_counts = db.execute(
        text(
            "SELECT COUNT(*) AS total, "
            "COUNT(*) FILTER (WHERE status='DRAFT') AS draft "
            f"FROM tunnel_plans{owner_filter}"
        ),
        params,
    ).mappings().one()

    return {
        "version": "1.0.0",
        "user": serialize_user(user),
        "counts": {
            "endpoints": dict(endpoint_counts),
            "jobs": dict(job_counts),
            "plans": dict(plan_counts),
        },
        "settings": {
            key: value
            for key, value in setting_values(db).items()
            if key in PUBLIC_SETTING_KEYS
        },
    }


@router.get("/jobs")
def list_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    status: str | None = Query(default=None, max_length=30),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(Job)

    if user.role not in ADMIN_ROLES:
        query = query.where(Job.owner_user_id == user.id)

    if status:
        query = query.where(Job.status == status.upper())

    rows = db.scalars(query.order_by(Job.id.desc()).limit(limit)).all()
    endpoint_ids = {row.endpoint_id for row in rows if row.endpoint_id}
    endpoint_map = {
        row.id: row.name
        for row in db.scalars(select(Endpoint).where(Endpoint.id.in_(endpoint_ids))).all()
    } if endpoint_ids else {}

    return {
        "items": [
            {
                "id": row.id,
                "owner_user_id": row.owner_user_id,
                "endpoint_id": row.endpoint_id,
                "endpoint_name": endpoint_map.get(row.endpoint_id),
                "job_type": row.job_type,
                "status": row.status,
                "progress": row.progress,
                "current_step": row.current_step,
                "error_message": redact(row.error_message),
                "created_at": iso(row.created_at),
                "started_at": iso(row.started_at),
                "finished_at": iso(row.finished_at),
            }
            for row in rows
        ]
    }


@router.get("/audit")
def list_audit(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None, max_length=150),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    query = select(AuditLog)

    if action:
        query = query.where(AuditLog.action == action)

    rows = db.scalars(query.order_by(AuditLog.id.desc()).limit(limit)).all()

    return {
        "items": [
            {
                "id": row.id,
                "actor_user_id": row.actor_user_id,
                "action": row.action,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "details": row.details,
                "created_at": iso(row.created_at),
            }
            for row in rows
        ]
    }


@router.get("/settings")
def read_settings(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    values = setting_values(db)

    if user.role not in ADMIN_ROLES:
        values = {
            key: value
            for key, value in values.items()
            if key in PUBLIC_SETTING_KEYS
        }

    return {
        "values": values,
        "environment": {
            "telegram_bot_enabled": settings.telegram_bot_enabled,
            "telegram_token_configured": bool(settings.telegram_bot_token),
            "bot_internal_key_configured": bool(settings.bot_internal_api_key),
            "smtp_configured": bool(
                os.getenv("SMTP_HOST")
                and os.getenv("SMTP_USERNAME")
                and os.getenv("SMTP_PASSWORD")
            ),
            "billing_mode": settings.billing_mode,
            "payments_enabled": settings.payments_enabled,
            "default_currency": settings.default_currency,
            "secondary_currency": settings.secondary_currency,
        },
    }


@router.put("/settings")
def update_settings(
    payload: SettingsUpdateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_super_admin(user)

    unknown = sorted(set(payload.values) - set(SAFE_SETTING_DEFAULTS))
    if unknown:
        raise HTTPException(
            status_code=400,
            detail={"code": "UNKNOWN_SETTING_KEYS", "keys": unknown},
        )

    for key, value in payload.values.items():
        row = db.scalar(select(AppSetting).where(AppSetting.key == key))
        value_json = json.dumps(value, ensure_ascii=False)

        if row is None:
            row = AppSetting(
                key=key,
                value_json=value_json,
                is_public=key in PUBLIC_SETTING_KEYS,
                updated_by_user_id=user.id,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
            db.add(row)
        else:
            row.value_json = value_json
            row.is_public = key in PUBLIC_SETTING_KEYS
            row.updated_by_user_id = user.id
            row.updated_at = utcnow()

    audit(
        db,
        user,
        "SYSTEM_SETTINGS_UPDATED",
        "APP_SETTING",
        None,
        {"keys": sorted(payload.values)},
    )
    db.commit()

    return {"status": "saved", "values": setting_values(db)}


@router.get("/users")
def list_users(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    rows = db.scalars(select(User).order_by(User.id.asc())).all()
    return {"items": [serialize_user(row) for row in rows]}


@router.post("/users")
def create_user(
    payload: UserCreateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_super_admin(user)

    row = User(
        username=payload.username.strip(),
        email=str(payload.email) if payload.email else None,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
        email_verified=False,
        telegram_id=payload.telegram_id,
        telegram_2fa_required=payload.role == UserRole.SUPER_ADMIN,
        must_change_password=True,
        created_at=utcnow(),
    )

    db.add(row)

    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="USER_ALREADY_EXISTS") from exc

    audit(
        db,
        user,
        "USER_CREATED",
        "USER",
        str(row.id),
        {"username": row.username, "role": row.role.value},
    )
    db.commit()
    db.refresh(row)
    return {"status": "created", "user": serialize_user(row)}


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_super_admin(user)
    target = db.get(User, user_id)

    if target is None:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    if target.id == user.id and payload.is_active is False:
        raise HTTPException(status_code=409, detail="CANNOT_DEACTIVATE_SELF")

    if target.id == user.id and payload.role is not None and payload.role != UserRole.SUPER_ADMIN:
        raise HTTPException(status_code=409, detail="CANNOT_DEMOTE_SELF")

    ensure_last_super_admin(
        db,
        target,
        new_role=payload.role,
        new_active=payload.is_active,
    )

    changes: dict[str, Any] = {}

    for field_name in ("email", "role", "is_active", "telegram_id"):
        value = getattr(payload, field_name)
        if value is None and field_name not in payload.model_fields_set:
            continue
        if field_name == "email" and value is not None:
            value = str(value)
        if field_name == "role" and value is not None:
            changes[field_name] = value.value
        else:
            changes[field_name] = value
        setattr(target, field_name, value)

    if payload.role == UserRole.SUPER_ADMIN:
        target.telegram_2fa_required = True

    try:
        audit(db, user, "USER_UPDATED", "USER", str(target.id), changes)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="USER_UPDATE_CONFLICT") from exc

    db.refresh(target)
    return {"status": "updated", "user": serialize_user(target)}


@router.post("/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    payload: PasswordResetRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_super_admin(user)
    target = db.get(User, user_id)

    if target is None:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    generated = payload.new_password is None
    new_password = payload.new_password or secrets.token_urlsafe(18)
    target.password_hash = hash_password(new_password)
    target.must_change_password = True

    audit(
        db,
        user,
        "USER_PASSWORD_RESET",
        "USER",
        str(target.id),
        {"generated": generated},
    )
    db.commit()

    return {
        "status": "reset",
        "temporary_password": new_password if generated else None,
        "must_change_password": True,
    }


@router.get("/xhttp-profiles")
def xhttp_profiles(user: User = Depends(current_user), db: Session = Depends(get_db)):
    values = setting_values(db)
    return {
        "profiles": [
            {
                "id": "VLESS_XHTTP",
                "name": "VLESS XHTTP Direct",
                "executable": True,
                "requires_domain": False,
                "requires_cdn": False,
                "transport_security": "internal-tls",
            },
            {
                "id": "VLESS_XHTTP_REALITY",
                "name": "VLESS XHTTP REALITY Direct",
                "executable": True,
                "requires_domain": False,
                "requires_cdn": False,
                "transport_security": "reality",
            },
            {
                "id": "VLESS_XHTTP_CDN",
                "name": "VLESS XHTTP TLS + CDN",
                "executable": False,
                "enabled": bool(values.get("xhttp_cdn_enabled")),
                "requires_domain": True,
                "requires_cdn": True,
                "provider": values.get("xhttp_cdn_provider"),
                "note": values.get("xhttp_cdn_note"),
            },
        ]
    }


@router.get("/deep-health")
def deep_health(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_admin(user)
    database_ok = db.execute(text("SELECT 1")).scalar_one() == 1

    try:
        redis_ok = bool(redis_client.ping())
    except Exception:
        redis_ok = False

    return {
        "status": "ok" if database_ok and redis_ok else "degraded",
        "version": "1.0.0",
        "database": database_ok,
        "redis": redis_ok,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.delete("/endpoints/{endpoint_id}/force")
def force_delete_endpoint(
    endpoint_id: int,
    confirmation: str = Query(min_length=6, max_length=100),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    require_super_admin(user)
    endpoint = db.execute(
        select(Endpoint).where(Endpoint.id == endpoint_id).with_for_update()
    ).scalar_one_or_none()

    if endpoint is None:
        raise HTTPException(status_code=404, detail="ENDPOINT_NOT_FOUND")

    if confirmation != endpoint.name:
        raise HTTPException(status_code=400, detail="ENDPOINT_NAME_CONFIRMATION_MISMATCH")

    plan_ids = list(
        db.execute(
            text(
                """
                SELECT DISTINCT plan_id
                FROM tunnel_plan_items
                WHERE endpoint_a_id=:endpoint_id
                   OR endpoint_b_id=:endpoint_id
                """
            ),
            {"endpoint_id": endpoint_id},
        ).scalars().all()
    )

    run_ids: list[int] = []
    if plan_ids:
        run_ids = list(
            db.execute(
                text("SELECT id FROM tunnel_plan_runs WHERE plan_id = ANY(:plan_ids)"),
                {"plan_ids": plan_ids},
            ).scalars().all()
        )

    precheck_job_ids = set(
        db.execute(
            text(
                """
                SELECT job_id
                FROM pair_prechecks
                WHERE endpoint_a_id=:endpoint_id
                   OR endpoint_b_id=:endpoint_id
                """
            ),
            {"endpoint_id": endpoint_id},
        ).scalars().all()
    )

    direct_job_ids = set(
        db.execute(
            text("SELECT id FROM jobs WHERE endpoint_id=:endpoint_id"),
            {"endpoint_id": endpoint_id},
        ).scalars().all()
    )
    job_ids = sorted(value for value in (precheck_job_ids | direct_job_ids) if value is not None)

    deleted = {
        "plans": len(plan_ids),
        "runs": len(run_ids),
        "jobs": len(job_ids),
        "prechecks": 0,
        "inventories": 0,
        "credentials": 0,
    }

    try:
        if run_ids:
            db.execute(
                text("DELETE FROM tunnel_plan_run_events WHERE run_id = ANY(:run_ids)"),
                {"run_ids": run_ids},
            )
            db.execute(
                text("DELETE FROM tunnel_plan_run_items WHERE run_id = ANY(:run_ids)"),
                {"run_ids": run_ids},
            )
            db.execute(
                text("DELETE FROM tunnel_plan_runs WHERE id = ANY(:run_ids)"),
                {"run_ids": run_ids},
            )

        if plan_ids:
            db.execute(
                text("DELETE FROM tunnel_plan_items WHERE plan_id = ANY(:plan_ids)"),
                {"plan_ids": plan_ids},
            )
            db.execute(
                text("DELETE FROM tunnel_plans WHERE id = ANY(:plan_ids)"),
                {"plan_ids": plan_ids},
            )

        result = db.execute(
            text(
                """
                DELETE FROM pair_prechecks
                WHERE endpoint_a_id=:endpoint_id
                   OR endpoint_b_id=:endpoint_id
                """
            ),
            {"endpoint_id": endpoint_id},
        )
        deleted["prechecks"] = result.rowcount or 0

        if job_ids:
            db.execute(
                text("DELETE FROM job_events WHERE job_id = ANY(:job_ids)"),
                {"job_ids": job_ids},
            )
            db.execute(
                text("DELETE FROM jobs WHERE id = ANY(:job_ids)"),
                {"job_ids": job_ids},
            )

        result = db.execute(
            text("DELETE FROM network_inventories WHERE endpoint_id=:endpoint_id"),
            {"endpoint_id": endpoint_id},
        )
        deleted["inventories"] = result.rowcount or 0

        result = db.execute(
            text("DELETE FROM endpoint_credentials WHERE endpoint_id=:endpoint_id"),
            {"endpoint_id": endpoint_id},
        )
        deleted["credentials"] = result.rowcount or 0

        endpoint_name = endpoint.name
        db.delete(endpoint)
        db.flush()

        audit(
            db,
            user,
            "ENDPOINT_FORCE_DELETED",
            "ENDPOINT",
            str(endpoint_id),
            {
                "name": endpoint_name,
                "deleted_dependencies": deleted,
                "warning": "Remote cleanup was skipped because this is a database force-delete.",
            },
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "status": "deleted",
        "mode": "force",
        "endpoint_id": endpoint_id,
        "name": endpoint_name,
        "deleted_dependencies": deleted,
    }
