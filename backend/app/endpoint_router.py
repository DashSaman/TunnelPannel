import ipaddress
import hmac
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from redis import Redis
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import (
    AuditLog,
    Endpoint,
    EndpointCredential,
    EndpointDraft,
    Job,
    JobEvent,
    PairPrecheck,
    NetworkInventory,
    TelegramProfile,
    User,
    UserRole,
)
from app.schemas import (
    InventoryConflictRequest,
    BotTelegramRequest,
    EndpointCreateRequest,
    EndpointUpdateRequest,
    PairPrecheckCreateRequest,
    EndpointDraftValueRequest,
)
from app.security import (
    decode_access_token,
    decrypt_secret,
    encrypt_secret,
)

router = APIRouter(prefix="/api/v1")
settings = get_settings()

redis_client = Redis.from_url(
    settings.redis_url,
    decode_responses=True,
)


def current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="AUTHORIZATION_REQUIRED",
        )

    scheme, _, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="INVALID_AUTHORIZATION_HEADER",
        )

    try:
        payload = decode_access_token(token)
        user_id = int(payload.get("sub", ""))
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=401,
            detail="INVALID_OR_EXPIRED_TOKEN",
        )

    user = db.get(User, user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="ACCOUNT_UNAVAILABLE",
        )

    return user


def require_bot_key(
    x_bot_api_key: str | None = Header(default=None),
):
    expected = settings.bot_internal_api_key or ""

    if not expected or not x_bot_api_key:
        raise HTTPException(
            status_code=403,
            detail="BOT_AUTH_REQUIRED",
        )

    if not hmac.compare_digest(
        expected,
        x_bot_api_key,
    ):
        raise HTTPException(
            status_code=403,
            detail="BOT_AUTH_INVALID",
        )


def linked_telegram_user(
    telegram_id: int,
    db: Session,
) -> User:
    user = db.scalar(
        select(User).where(
            User.telegram_id == telegram_id
        )
    )

    if not user or not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="TELEGRAM_ACCOUNT_NOT_LINKED",
        )

    return user


def suggest_zone(location: str | None) -> str:
    value = (location or "").strip().lower()

    iran_words = {
        "iran",
        "ایران",
        "tehran",
        "تهران",
        "mashhad",
        "مشهد",
        "shiraz",
        "شیراز",
        "tabriz",
        "تبریز",
        "isfahan",
        "اصفهان",
    }

    if any(word in value for word in iran_words):
        return "IRAN"

    if value:
        return "FOREIGN"

    return "UNKNOWN"


def endpoint_to_dict(endpoint: Endpoint) -> dict:
    return {
        "id": endpoint.id,
        "name": endpoint.name,
        "device_type": endpoint.device_type,
        "host": endpoint.host,
        "port": endpoint.port,
        "ssh_username": endpoint.ssh_username,
        "auth_method": endpoint.auth_method,
        "display_location": endpoint.display_location,
        "technical_zone": endpoint.technical_zone,
        "description": endpoint.description,
        "status": endpoint.status,
        "detected_os": endpoint.detected_os,
        "detected_version": endpoint.detected_version,
        "detected_hostname": endpoint.detected_hostname,
        "detected_arch": endpoint.detected_arch,
        "primary_interface": endpoint.primary_interface,
        "public_ip": endpoint.public_ip,
        "last_error": endpoint.last_error,
        "created_at": endpoint.created_at.isoformat()
        if endpoint.created_at
        else None,
    }


def create_endpoint_and_job(
    db: Session,
    user: User,
    data: dict,
) -> tuple[Endpoint, Job]:
    requested_zone = (
        data.get("technical_zone")
        or "AUTO"
    ).upper()

    if requested_zone not in {
        "IRAN",
        "FOREIGN",
        "UNKNOWN",
    }:
        requested_zone = suggest_zone(
            data.get("display_location")
        )

    auth_method = (
        data.get("auth_method")
        or ""
    ).upper()

    if auth_method not in {
        "PASSWORD",
        "PRIVATE_KEY",
    }:
        raise HTTPException(
            status_code=400,
            detail="INVALID_AUTH_METHOD",
        )

    sudo_mode = (
        data.get("sudo_mode")
        or "NONE"
    ).upper()

    if sudo_mode not in {
        "NONE",
        "PASSWORDLESS",
        "PASSWORD",
    }:
        raise HTTPException(
            status_code=400,
            detail="INVALID_SUDO_MODE",
        )

    endpoint = Endpoint(
        owner_user_id=user.id,
        name=data["name"].strip(),
        device_type="LINUX",
        host=data["host"].strip(),
        port=int(data.get("port") or 22),
        ssh_username=data["ssh_username"].strip(),
        auth_method=auth_method,
        display_location=(
            data.get("display_location") or ""
        ).strip() or None,
        technical_zone=requested_zone,
        description=(
            data.get("description") or ""
        ).strip() or None,
        status="PENDING",
    )

    db.add(endpoint)
    db.flush()

    secret_payload = {
        "auth_method": auth_method,
        "secret": data["secret"],
        "sudo_mode": sudo_mode,
        "sudo_password": data.get("sudo_password"),
    }

    credential = EndpointCredential(
        endpoint_id=endpoint.id,
        encrypted_blob=encrypt_secret(
            json.dumps(
                secret_payload,
                ensure_ascii=False,
            )
        ),
    )

    job = Job(
        owner_user_id=user.id,
        endpoint_id=endpoint.id,
        job_type="ENDPOINT_DISCOVERY",
        status="QUEUED",
        progress=0,
        current_step="queue",
    )

    db.add(credential)
    db.add(job)
    db.flush()

    db.add(
        JobEvent(
            job_id=job.id,
            level="INFO",
            step="queue",
            public_message=(
                "Endpoint در صف بررسی و اتصال قرار گرفت."
            ),
        )
    )

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="ENDPOINT_CREATED",
            target_type="ENDPOINT",
            target_id=str(endpoint.id),
            details=(
                f"Linux endpoint {endpoint.name} created"
            ),
        )
    )

    db.commit()

    try:
        redis_client.rpush(
            "netauto:jobs",
            json.dumps(
                {
                    "id": job.id,
                    "type": job.job_type,
                }
            ),
        )
    except Exception as exc:
        job.status = "FAILED"
        job.error_message = (
            f"QUEUE_ERROR: {type(exc).__name__}"
        )
        endpoint.status = "ERROR"
        endpoint.last_error = "QUEUE_ERROR"
        db.commit()
        raise HTTPException(
            status_code=503,
            detail="JOB_QUEUE_UNAVAILABLE",
        ) from exc

    return endpoint, job


@router.post("/endpoints")
def create_endpoint(
    payload: EndpointCreateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    endpoint, job = create_endpoint_and_job(
        db,
        user,
        payload.model_dump(),
    )

    return {
        "status": "ok",
        "endpoint": endpoint_to_dict(endpoint),
        "job_id": job.id,
    }


@router.get("/endpoints")
def list_endpoints(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(Endpoint).order_by(
        Endpoint.id.desc()
    )

    if user.role not in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }:
        query = query.where(
            Endpoint.owner_user_id == user.id
        )

    endpoints = db.scalars(query).all()

    return {
        "items": [
            endpoint_with_inventory(db, item)
            for item in endpoints
        ]
    }


@router.get("/jobs/{job_id}")
def read_job(
    job_id: int,
    after_id: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    job = db.get(Job, job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="JOB_NOT_FOUND",
        )

    if (
        user.role
        not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and job.owner_user_id != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="JOB_ACCESS_DENIED",
        )

    events = db.scalars(
        select(JobEvent)
        .where(
            JobEvent.job_id == job.id,
            JobEvent.id > after_id,
        )
        .order_by(JobEvent.id.asc())
    ).all()

    technical = user.role in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }

    return {
        "id": job.id,
        "status": job.status,
        "progress": job.progress,
        "current_step": job.current_step,
        "error_message": job.error_message,
        "events": [
            {
                "id": event.id,
                "level": event.level,
                "step": event.step,
                "message": event.public_message,
                "command": event.command
                if technical
                else None,
                "output": event.output
                if technical
                else None,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ],
    }


DRAFT_STEPS = {
    "name": {
        "prompt": "نام نمایشی Endpoint را وارد کنید.",
        "type": "text",
    },
    "host": {
        "prompt": "IP یا دامنه سرور را وارد کنید.",
        "type": "text",
    },
    "port": {
        "prompt": "پورت SSH را وارد کنید. پیش‌فرض 22 است.",
        "type": "text",
    },
    "ssh_username": {
        "prompt": "نام کاربری SSH را وارد کنید.",
        "type": "text",
    },
    "display_location": {
        "prompt": (
            "کشور، شهر و دیتاسنتر را وارد کنید؛ "
            "مثلاً Germany — Frankfurt — Hetzner."
        ),
        "type": "text",
    },
    "auth_method": {
        "prompt": "روش ورود را انتخاب کنید.",
        "type": "choice",
        "choices": [
            "PASSWORD",
            "PRIVATE_KEY",
        ],
    },
    "secret": {
        "prompt": (
            "رمز SSH یا Private Key را ارسال کنید. "
            "این پیام پس از دریافت حذف می‌شود."
        ),
        "type": "secret",
    },
    "sudo_mode": {
        "prompt": "نوع دسترسی مدیریتی را انتخاب کنید.",
        "type": "choice",
        "choices": [
            "NONE",
            "PASSWORDLESS",
            "PASSWORD",
        ],
    },
    "sudo_password": {
        "prompt": (
            "رمز sudo را ارسال کنید. "
            "این پیام پس از دریافت حذف می‌شود."
        ),
        "type": "secret",
    },
    "description": {
        "prompt": (
            "توضیحات Endpoint را وارد کنید؛ "
            "برای خالی‌گذاشتن فقط - بفرستید."
        ),
        "type": "text",
    },
    "review": {
        "prompt": "اطلاعات را بررسی و تأیید کنید.",
        "type": "review",
    },
}


def draft_response(
    draft: EndpointDraft,
) -> dict:
    data = json.loads(
        draft.payload_json or "{}"
    )

    response = {
        "draft_id": draft.id,
        "step": draft.current_step,
        **DRAFT_STEPS[draft.current_step],
    }

    if draft.current_step == "review":
        response["summary"] = {
            "name": data.get("name"),
            "host": data.get("host"),
            "port": data.get("port"),
            "ssh_username": data.get("ssh_username"),
            "display_location": data.get(
                "display_location"
            ),
            "technical_zone": data.get(
                "technical_zone"
            ),
            "auth_method": data.get(
                "auth_method"
            ),
            "sudo_mode": data.get("sudo_mode"),
            "description": data.get("description"),
        }

    return response


@router.post(
    "/bot/endpoint-drafts/start",
    dependencies=[Depends(require_bot_key)],
)
def start_bot_endpoint_draft(
    payload: BotTelegramRequest,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        payload.telegram_id,
        db,
    )

    existing = db.scalar(
        select(EndpointDraft).where(
            EndpointDraft.owner_user_id == user.id,
            EndpointDraft.channel == "TELEGRAM",
        )
    )

    if existing:
        db.delete(existing)
        db.flush()

    draft = EndpointDraft(
        owner_user_id=user.id,
        channel="TELEGRAM",
        current_step="name",
        payload_json="{}",
    )

    db.add(draft)
    db.commit()
    db.refresh(draft)

    return draft_response(draft)


@router.get(
    "/bot/endpoint-drafts/{telegram_id}",
    dependencies=[Depends(require_bot_key)],
)
def get_bot_endpoint_draft(
    telegram_id: int,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        telegram_id,
        db,
    )

    draft = db.scalar(
        select(EndpointDraft).where(
            EndpointDraft.owner_user_id == user.id,
            EndpointDraft.channel == "TELEGRAM",
        )
    )

    if not draft:
        return {
            "active": False,
        }

    return {
        "active": True,
        **draft_response(draft),
    }


@router.post(
    "/bot/endpoint-drafts/advance",
    dependencies=[Depends(require_bot_key)],
)
def advance_bot_endpoint_draft(
    payload: EndpointDraftValueRequest,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        payload.telegram_id,
        db,
    )

    draft = db.scalar(
        select(EndpointDraft).where(
            EndpointDraft.owner_user_id == user.id,
            EndpointDraft.channel == "TELEGRAM",
        )
    )

    if not draft:
        raise HTTPException(
            status_code=404,
            detail="DRAFT_NOT_FOUND",
        )

    data = json.loads(
        draft.payload_json or "{}"
    )

    step = draft.current_step
    value = payload.value.strip()

    if step == "review":
        if value.startswith("ZONE:"):
            zone = value.split(":", 1)[1].upper()

            if zone not in {
                "IRAN",
                "FOREIGN",
                "UNKNOWN",
            }:
                raise HTTPException(
                    status_code=400,
                    detail="INVALID_ZONE",
                )

            data["technical_zone"] = zone
            draft.payload_json = json.dumps(
                data,
                ensure_ascii=False,
            )
            db.commit()
            return draft_response(draft)

        raise HTTPException(
            status_code=400,
            detail="REVIEW_REQUIRES_CONFIRMATION",
        )

    if step == "port":
        try:
            port = int(value or "22")
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="INVALID_PORT",
            ) from exc

        if not 1 <= port <= 65535:
            raise HTTPException(
                status_code=400,
                detail="INVALID_PORT",
            )

        data["port"] = port
        draft.current_step = "ssh_username"

    elif step == "auth_method":
        method = value.upper()

        if method not in {
            "PASSWORD",
            "PRIVATE_KEY",
        }:
            raise HTTPException(
                status_code=400,
                detail="INVALID_AUTH_METHOD",
            )

        data["auth_method"] = method
        draft.current_step = "secret"

    elif step == "secret":
        data["secret_encrypted"] = encrypt_secret(
            value
        )
        draft.current_step = "sudo_mode"

    elif step == "sudo_mode":
        mode = value.upper()

        if mode not in {
            "NONE",
            "PASSWORDLESS",
            "PASSWORD",
        }:
            raise HTTPException(
                status_code=400,
                detail="INVALID_SUDO_MODE",
            )

        data["sudo_mode"] = mode

        draft.current_step = (
            "sudo_password"
            if mode == "PASSWORD"
            else "description"
        )

    elif step == "sudo_password":
        data["sudo_password_encrypted"] = (
            encrypt_secret(value)
        )
        draft.current_step = "description"

    elif step == "description":
        data["description"] = (
            None if value == "-" else value
        )
        draft.current_step = "review"

    else:
        data[step] = value

        next_steps = {
            "name": "host",
            "host": "port",
            "ssh_username": "display_location",
            "display_location": "auth_method",
        }

        draft.current_step = next_steps[step]

        if step == "display_location":
            data["technical_zone"] = (
                suggest_zone(value)
            )

    draft.payload_json = json.dumps(
        data,
        ensure_ascii=False,
    )

    draft.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(draft)

    return draft_response(draft)


@router.post(
    "/bot/endpoint-drafts/cancel",
    dependencies=[Depends(require_bot_key)],
)
def cancel_bot_endpoint_draft(
    payload: BotTelegramRequest,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        payload.telegram_id,
        db,
    )

    draft = db.scalar(
        select(EndpointDraft).where(
            EndpointDraft.owner_user_id == user.id,
            EndpointDraft.channel == "TELEGRAM",
        )
    )

    if draft:
        db.delete(draft)
        db.commit()

    return {
        "status": "cancelled",
    }


@router.post(
    "/bot/endpoint-drafts/commit",
    dependencies=[Depends(require_bot_key)],
)
def commit_bot_endpoint_draft(
    payload: BotTelegramRequest,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        payload.telegram_id,
        db,
    )

    draft = db.scalar(
        select(EndpointDraft).where(
            EndpointDraft.owner_user_id == user.id,
            EndpointDraft.channel == "TELEGRAM",
        )
    )

    if not draft or draft.current_step != "review":
        raise HTTPException(
            status_code=400,
            detail="DRAFT_NOT_READY",
        )

    data = json.loads(
        draft.payload_json
    )

    data["secret"] = decrypt_secret(
        data.pop("secret_encrypted")
    )

    sudo_encrypted = data.pop(
        "sudo_password_encrypted",
        None,
    )

    data["sudo_password"] = (
        decrypt_secret(sudo_encrypted)
        if sudo_encrypted
        else None
    )

    endpoint, job = create_endpoint_and_job(
        db,
        user,
        data,
    )

    db.delete(draft)
    db.commit()

    return {
        "status": "ok",
        "endpoint": endpoint_to_dict(endpoint),
        "job_id": job.id,
    }


@router.get(
    "/bot/endpoints/{telegram_id}",
    dependencies=[Depends(require_bot_key)],
)
def list_bot_endpoints(
    telegram_id: int,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        telegram_id,
        db,
    )

    query = select(Endpoint).order_by(
        Endpoint.id.desc()
    )

    if user.role not in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }:
        query = query.where(
            Endpoint.owner_user_id == user.id
        )

    items = db.scalars(query).all()

    return {
        "items": [
            endpoint_with_inventory(db, item)
            for item in items
        ]
    }



@router.post(
    "/bot/endpoint-drafts/back",
    dependencies=[Depends(require_bot_key)],
)
def back_bot_endpoint_draft(
    payload: BotTelegramRequest,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        payload.telegram_id,
        db,
    )

    draft = db.scalar(
        select(EndpointDraft).where(
            EndpointDraft.owner_user_id == user.id,
            EndpointDraft.channel == "TELEGRAM",
        )
    )

    if not draft:
        raise HTTPException(
            status_code=404,
            detail="DRAFT_NOT_FOUND",
        )

    data = json.loads(
        draft.payload_json or "{}"
    )

    step = draft.current_step

    if step == "name":
        return draft_response(draft)

    if step == "review":
        previous = "description"

    elif step == "description":
        previous = (
            "sudo_password"
            if data.get("sudo_mode") == "PASSWORD"
            else "sudo_mode"
        )

    else:
        previous_steps = {
            "host": "name",
            "port": "host",
            "ssh_username": "port",
            "display_location": "ssh_username",
            "auth_method": "display_location",
            "secret": "auth_method",
            "sudo_mode": "secret",
            "sudo_password": "sudo_mode",
        }

        previous = previous_steps.get(
            step,
            "name",
        )

    draft.current_step = previous
    draft.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(draft)

    return draft_response(draft)


@router.get(
    "/bot/jobs/{telegram_id}/{job_id}",
    dependencies=[Depends(require_bot_key)],
)
def read_bot_job(
    telegram_id: int,
    job_id: int,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        telegram_id,
        db,
    )

    job = db.get(Job, job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="JOB_NOT_FOUND",
        )

    if (
        user.role not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and job.owner_user_id != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="JOB_ACCESS_DENIED",
        )

    events = db.scalars(
        select(JobEvent)
        .where(JobEvent.job_id == job.id)
        .order_by(JobEvent.id.asc())
    ).all()

    technical = user.role in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }

    return {
        "id": job.id,
        "status": job.status,
        "progress": job.progress,
        "current_step": job.current_step,
        "error_message": job.error_message,
        "technical_access": technical,
        "events": [
            {
                "id": event.id,
                "level": event.level,
                "step": event.step,
                "message": event.public_message,
                "command": (
                    event.command
                    if technical
                    else None
                ),
                "output": (
                    event.output
                    if technical
                    else None
                ),
                "created_at": (
                    event.created_at.isoformat()
                    if event.created_at
                    else None
                ),
            }
            for event in events
        ],
    }



def remove_endpoint(
    db: Session,
    user: User,
    endpoint_id: int,
) -> str:
    endpoint = db.get(
        Endpoint,
        endpoint_id,
    )

    if not endpoint:
        raise HTTPException(
            status_code=404,
            detail="ENDPOINT_NOT_FOUND",
        )

    if (
        user.role not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and endpoint.owner_user_id != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="ENDPOINT_ACCESS_DENIED",
        )

    endpoint_name = endpoint.name

    try:
        active_job = db.execute(
            text(
                """
                SELECT id, job_type, status
                FROM jobs
                WHERE endpoint_id = :endpoint_id
                  AND status IN (
                    'QUEUED',
                    'RUNNING',
                    'RETRY'
                  )
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        ).mappings().first()

        if active_job:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "ENDPOINT_HAS_ACTIVE_JOB",
                    "job_id": active_job["id"],
                    "job_type": active_job["job_type"],
                    "status": active_job["status"],
                },
            )

        active_precheck = db.execute(
            text(
                """
                SELECT
                    p.id AS precheck_id,
                    j.id AS job_id,
                    j.status
                FROM pair_prechecks AS p
                JOIN jobs AS j
                  ON j.id = p.job_id
                WHERE (
                    p.endpoint_a_id = :endpoint_id
                    OR p.endpoint_b_id = :endpoint_id
                )
                  AND j.status IN (
                    'QUEUED',
                    'RUNNING',
                    'RETRY'
                  )
                ORDER BY p.id DESC
                LIMIT 1
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        ).mappings().first()

        if active_precheck:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": (
                        "ENDPOINT_HAS_ACTIVE_PRECHECK"
                    ),
                    "precheck_id": (
                        active_precheck["precheck_id"]
                    ),
                    "job_id": (
                        active_precheck["job_id"]
                    ),
                    "status": (
                        active_precheck["status"]
                    ),
                },
            )

        active_run = db.execute(
            text(
                """
                SELECT DISTINCT
                    r.id AS run_id,
                    p.id AS plan_id,
                    p.name AS plan_name,
                    r.status
                FROM tunnel_plan_items AS i
                JOIN tunnel_plans AS p
                  ON p.id = i.plan_id
                JOIN tunnel_plan_runs AS r
                  ON r.plan_id = p.id
                WHERE (
                    i.endpoint_a_id = :endpoint_id
                    OR i.endpoint_b_id = :endpoint_id
                )
                  AND r.status IN (
                    'QUEUED',
                    'RUNNING',
                    'CANCEL_REQUESTED',
                    'ROLLING_BACK'
                  )
                ORDER BY r.id DESC
                LIMIT 1
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        ).mappings().first()

        if active_run:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": (
                        "ENDPOINT_HAS_ACTIVE_TUNNEL_RUN"
                    ),
                    "run_id": active_run["run_id"],
                    "plan_id": active_run["plan_id"],
                    "plan_name": active_run["plan_name"],
                    "status": active_run["status"],
                },
            )

        plans = db.execute(
            text(
                """
                SELECT DISTINCT
                    p.id,
                    p.name,
                    p.status
                FROM tunnel_plans AS p
                JOIN tunnel_plan_items AS i
                  ON i.plan_id = p.id
                WHERE (
                    i.endpoint_a_id = :endpoint_id
                    OR i.endpoint_b_id = :endpoint_id
                )
                ORDER BY p.id
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        ).mappings().all()

        protected_plans = [
            {
                "id": row["id"],
                "name": row["name"],
                "status": row["status"],
            }
            for row in plans
            if row["status"] != "DRAFT"
        ]

        if protected_plans:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": (
                        "ENDPOINT_HAS_PERSISTED_TUNNEL_PLANS"
                    ),
                    "plans": protected_plans[:20],
                    "message": (
                        "Rollback or remove the related "
                        "tunnel plans before deleting "
                        "this endpoint."
                    ),
                },
            )

        deleted = {
            "draft_plans": 0,
            "prechecks": 0,
            "jobs": 0,
            "inventories": 0,
            "credentials": 0,
        }

        draft_plan_ids = [
            row["id"]
            for row in plans
            if row["status"] == "DRAFT"
        ]

        for plan_id in draft_plan_ids:
            run_ids = list(
                db.execute(
                    text(
                        """
                        SELECT id
                        FROM tunnel_plan_runs
                        WHERE plan_id = :plan_id
                        """
                    ),
                    {
                        "plan_id": plan_id,
                    },
                ).scalars().all()
            )

            for run_id in run_ids:
                db.execute(
                    text(
                        """
                        DELETE FROM
                            tunnel_plan_run_events
                        WHERE run_id = :run_id
                        """
                    ),
                    {
                        "run_id": run_id,
                    },
                )
                db.execute(
                    text(
                        """
                        DELETE FROM
                            tunnel_plan_run_items
                        WHERE run_id = :run_id
                        """
                    ),
                    {
                        "run_id": run_id,
                    },
                )

            db.execute(
                text(
                    """
                    DELETE FROM tunnel_plan_runs
                    WHERE plan_id = :plan_id
                    """
                ),
                {
                    "plan_id": plan_id,
                },
            )
            db.execute(
                text(
                    """
                    DELETE FROM tunnel_plan_items
                    WHERE plan_id = :plan_id
                    """
                ),
                {
                    "plan_id": plan_id,
                },
            )
            db.execute(
                text(
                    """
                    DELETE FROM tunnel_plans
                    WHERE id = :plan_id
                    """
                ),
                {
                    "plan_id": plan_id,
                },
            )
            deleted["draft_plans"] += 1

        precheck_rows = db.execute(
            text(
                """
                SELECT id, job_id
                FROM pair_prechecks
                WHERE endpoint_a_id = :endpoint_id
                   OR endpoint_b_id = :endpoint_id
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        ).mappings().all()

        precheck_job_ids = {
            row["job_id"]
            for row in precheck_rows
            if row["job_id"] is not None
        }

        result = db.execute(
            text(
                """
                DELETE FROM pair_prechecks
                WHERE endpoint_a_id = :endpoint_id
                   OR endpoint_b_id = :endpoint_id
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        )
        deleted["prechecks"] = (
            result.rowcount or 0
        )

        direct_job_ids = set(
            db.execute(
                text(
                    """
                    SELECT id
                    FROM jobs
                    WHERE endpoint_id = :endpoint_id
                    """
                ),
                {
                    "endpoint_id": endpoint.id,
                },
            ).scalars().all()
        )

        all_job_ids = sorted(
            direct_job_ids
            | precheck_job_ids
        )

        for job_id in all_job_ids:
            db.execute(
                text(
                    """
                    DELETE FROM job_events
                    WHERE job_id = :job_id
                    """
                ),
                {
                    "job_id": job_id,
                },
            )
            result = db.execute(
                text(
                    """
                    DELETE FROM jobs
                    WHERE id = :job_id
                    """
                ),
                {
                    "job_id": job_id,
                },
            )
            deleted["jobs"] += (
                result.rowcount or 0
            )

        result = db.execute(
            text(
                """
                DELETE FROM network_inventories
                WHERE endpoint_id = :endpoint_id
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        )
        deleted["inventories"] = (
            result.rowcount or 0
        )

        result = db.execute(
            text(
                """
                DELETE FROM endpoint_credentials
                WHERE endpoint_id = :endpoint_id
                """
            ),
            {
                "endpoint_id": endpoint.id,
            },
        )
        deleted["credentials"] = (
            result.rowcount or 0
        )

        db.delete(endpoint)

        db.add(
            AuditLog(
                actor_user_id=user.id,
                action="ENDPOINT_DELETED",
                target_type="ENDPOINT",
                target_id=str(endpoint_id),
                details=json.dumps(
                    {
                        "name": endpoint_name,
                        "deleted_dependencies": deleted,
                    },
                    ensure_ascii=False,
                ),
            )
        )

        db.commit()
        return endpoint_name

    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ENDPOINT_DELETE_CONFLICT",
                "message": (
                    "The endpoint still has a protected "
                    "database reference."
                ),
                "error_type": type(exc).__name__,
            },
        ) from exc


@router.delete("/endpoints/{endpoint_id}")
def delete_endpoint(
    endpoint_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    name = remove_endpoint(
        db,
        user,
        endpoint_id,
    )

    return {
        "status": "deleted",
        "endpoint_id": endpoint_id,
        "name": name,
    }


@router.delete(
    "/bot/endpoints/{telegram_id}/{endpoint_id}",
    dependencies=[Depends(require_bot_key)],
)
def delete_bot_endpoint(
    telegram_id: int,
    endpoint_id: int,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        telegram_id,
        db,
    )

    name = remove_endpoint(
        db,
        user,
        endpoint_id,
    )

    return {
        "status": "deleted",
        "endpoint_id": endpoint_id,
        "name": name,
    }



def get_accessible_endpoint(
    db: Session,
    user: User,
    endpoint_id: int,
) -> Endpoint:
    endpoint = db.get(
        Endpoint,
        endpoint_id,
    )

    if not endpoint:
        raise HTTPException(
            status_code=404,
            detail="ENDPOINT_NOT_FOUND",
        )

    if (
        user.role not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and endpoint.owner_user_id != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="ENDPOINT_ACCESS_DENIED",
        )

    return endpoint


@router.get("/endpoints/{endpoint_id}")
def read_endpoint_detail(
    endpoint_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    endpoint = get_accessible_endpoint(
        db,
        user,
        endpoint_id,
    )

    credential = db.scalar(
        select(EndpointCredential).where(
            EndpointCredential.endpoint_id
            == endpoint.id
        )
    )

    sudo_mode = "NONE"
    has_secret = False
    has_sudo_password = False

    if credential:
        try:
            secret_data = json.loads(
                decrypt_secret(
                    credential.encrypted_blob
                )
            )

            sudo_mode = secret_data.get(
                "sudo_mode",
                "NONE",
            )

            has_secret = bool(
                secret_data.get("secret")
            )

            has_sudo_password = bool(
                secret_data.get("sudo_password")
            )

        except Exception:
            pass

    result = endpoint_to_dict(endpoint)

    result.update(
        {
            "sudo_mode": sudo_mode,
            "has_secret": has_secret,
            "has_sudo_password": (
                has_sudo_password
            ),
        }
    )

    return result


@router.put("/endpoints/{endpoint_id}")
def update_endpoint(
    endpoint_id: int,
    payload: EndpointUpdateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    endpoint = get_accessible_endpoint(
        db,
        user,
        endpoint_id,
    )

    active_job = db.scalar(
        select(Job).where(
            Job.endpoint_id == endpoint.id,
            Job.status.in_(
                {
                    "QUEUED",
                    "RUNNING",
                    "RETRY",
                }
            ),
        )
    )

    if active_job:
        raise HTTPException(
            status_code=409,
            detail="ENDPOINT_HAS_ACTIVE_JOB",
        )

    credential = db.scalar(
        select(EndpointCredential).where(
            EndpointCredential.endpoint_id
            == endpoint.id
        )
    )

    if not credential:
        raise HTTPException(
            status_code=404,
            detail="ENDPOINT_CREDENTIAL_NOT_FOUND",
        )

    try:
        secret_data = json.loads(
            decrypt_secret(
                credential.encrypted_blob
            )
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="ENDPOINT_CREDENTIAL_INVALID",
        ) from exc

    data = payload.model_dump(
        exclude_unset=True
    )

    for field in (
        "name",
        "host",
        "ssh_username",
    ):
        if field in data and data[field] is not None:
            setattr(
                endpoint,
                field,
                data[field].strip(),
            )

    if (
        "port" in data
        and data["port"] is not None
    ):
        endpoint.port = data["port"]

    if "display_location" in data:
        endpoint.display_location = (
            data["display_location"].strip()
            if data["display_location"]
            else None
        )

    if "description" in data:
        endpoint.description = (
            data["description"].strip()
            if data["description"]
            else None
        )

    current_auth_method = (
        secret_data.get("auth_method")
        or endpoint.auth_method
    ).upper()

    new_auth_method = (
        data.get("auth_method")
        or current_auth_method
    ).upper()

    if new_auth_method not in {
        "PASSWORD",
        "PRIVATE_KEY",
    }:
        raise HTTPException(
            status_code=400,
            detail="INVALID_AUTH_METHOD",
        )

    new_secret = data.get("secret")

    if (
        new_auth_method != current_auth_method
        and not new_secret
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "AUTH_METHOD_CHANGE_REQUIRES_SECRET"
            ),
        )

    if new_secret:
        secret_data["secret"] = new_secret

    if not secret_data.get("secret"):
        raise HTTPException(
            status_code=400,
            detail="SSH_SECRET_REQUIRED",
        )

    endpoint.auth_method = new_auth_method
    secret_data["auth_method"] = new_auth_method

    sudo_mode = (
        data.get("sudo_mode")
        or secret_data.get("sudo_mode")
        or "NONE"
    ).upper()

    if sudo_mode not in {
        "NONE",
        "PASSWORDLESS",
        "PASSWORD",
    }:
        raise HTTPException(
            status_code=400,
            detail="INVALID_SUDO_MODE",
        )

    secret_data["sudo_mode"] = sudo_mode

    new_sudo_password = data.get(
        "sudo_password"
    )

    if new_sudo_password:
        secret_data["sudo_password"] = (
            new_sudo_password
        )

    if sudo_mode != "PASSWORD":
        secret_data["sudo_password"] = None

    if (
        sudo_mode == "PASSWORD"
        and not secret_data.get(
            "sudo_password"
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="SUDO_PASSWORD_REQUIRED",
        )

    credential.encrypted_blob = encrypt_secret(
        json.dumps(
            secret_data,
            ensure_ascii=False,
        )
    )

    endpoint.status = "PENDING"
    endpoint.last_error = None
    endpoint.updated_at = datetime.utcnow()

    job = Job(
        owner_user_id=user.id,
        endpoint_id=endpoint.id,
        job_type="ENDPOINT_DISCOVERY",
        status="QUEUED",
        progress=0,
        current_step="queue",
    )

    db.add(job)
    db.flush()

    db.add(
        JobEvent(
            job_id=job.id,
            level="INFO",
            step="queue",
            public_message=(
                "Endpoint updated and queued "
                "for verification."
            ),
        )
    )

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="ENDPOINT_UPDATED",
            target_type="ENDPOINT",
            target_id=str(endpoint.id),
            details=(
                f"Endpoint {endpoint.name} updated"
            ),
        )
    )

    db.commit()

    try:
        redis_client.rpush(
            "netauto:jobs",
            json.dumps(
                {
                    "id": job.id,
                    "type": job.job_type,
                }
            ),
        )

    except Exception as exc:
        endpoint.status = "ERROR"
        endpoint.last_error = "QUEUE_ERROR"

        job.status = "FAILED"
        job.error_message = (
            f"QUEUE_ERROR: {type(exc).__name__}"
        )

        db.commit()

        raise HTTPException(
            status_code=503,
            detail="JOB_QUEUE_UNAVAILABLE",
        ) from exc

    return {
        "status": "ok",
        "endpoint": endpoint_to_dict(
            endpoint
        ),
        "job_id": job.id,
    }



@router.post("/prechecks")
def create_pair_precheck(
    payload: PairPrecheckCreateRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if payload.endpoint_a_id == payload.endpoint_b_id:
        raise HTTPException(
            status_code=400,
            detail="ENDPOINTS_MUST_BE_DIFFERENT",
        )

    endpoint_a = get_accessible_endpoint(
        db,
        user,
        payload.endpoint_a_id,
    )
    endpoint_b = get_accessible_endpoint(
        db,
        user,
        payload.endpoint_b_id,
    )

    if (
        endpoint_a.status != "READY"
        or endpoint_b.status != "READY"
    ):
        raise HTTPException(
            status_code=409,
            detail="BOTH_ENDPOINTS_MUST_BE_READY",
        )

    job = Job(
        owner_user_id=user.id,
        endpoint_id=endpoint_a.id,
        job_type="ENDPOINT_PAIR_PRECHECK",
        status="QUEUED",
        progress=0,
        current_step="queue",
    )
    db.add(job)
    db.flush()

    precheck = PairPrecheck(
        owner_user_id=user.id,
        endpoint_a_id=endpoint_a.id,
        endpoint_b_id=endpoint_b.id,
        job_id=job.id,
        status="QUEUED",
        result_json="{}",
    )
    db.add(precheck)

    db.add(
        JobEvent(
            job_id=job.id,
            level="INFO",
            step="queue",
            public_message=(
                "Bidirectional connectivity precheck queued."
            ),
        )
    )

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="PAIR_PRECHECK_CREATED",
            target_type="PAIR_PRECHECK",
            target_id=str(job.id),
            details=(
                f"Endpoint {endpoint_a.id} "
                f"to endpoint {endpoint_b.id}"
            ),
        )
    )

    db.commit()

    try:
        redis_client.rpush(
            "netauto:jobs",
            json.dumps(
                {
                    "id": job.id,
                    "type": job.job_type,
                }
            ),
        )
    except Exception as exc:
        job.status = "FAILED"
        job.error_message = "JOB_QUEUE_UNAVAILABLE"
        precheck.status = "FAILED"
        db.commit()

        raise HTTPException(
            status_code=503,
            detail="JOB_QUEUE_UNAVAILABLE",
        ) from exc

    return {
        "status": "ok",
        "precheck_id": precheck.id,
        "job_id": job.id,
        "endpoint_a": endpoint_to_dict(endpoint_a),
        "endpoint_b": endpoint_to_dict(endpoint_b),
    }


@router.get("/prechecks/{precheck_id}")
def read_pair_precheck(
    precheck_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    precheck = db.get(
        PairPrecheck,
        precheck_id,
    )

    if not precheck:
        raise HTTPException(
            status_code=404,
            detail="PRECHECK_NOT_FOUND",
        )

    if (
        user.role not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and precheck.owner_user_id != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="PRECHECK_ACCESS_DENIED",
        )

    return {
        "id": precheck.id,
        "job_id": precheck.job_id,
        "endpoint_a_id": precheck.endpoint_a_id,
        "endpoint_b_id": precheck.endpoint_b_id,
        "status": precheck.status,
        "result": json.loads(
            precheck.result_json or "{}"
        ),
    }



def inventory_to_dict(
    inventory: NetworkInventory,
    technical: bool = False,
) -> dict:
    try:
        summary = json.loads(
            inventory.summary_json or "{}"
        )
    except Exception:
        summary = {}

    try:
        data = json.loads(
            inventory.inventory_json or "{}"
        )
    except Exception:
        data = {}

    if not technical:
        data.pop("raw", None)

    return {
        "id": inventory.id,
        "endpoint_id": inventory.endpoint_id,
        "status": inventory.status,
        "summary": summary,
        "data": data,
        "last_error": inventory.last_error,
        "scanned_at": (
            inventory.scanned_at.isoformat()
            if inventory.scanned_at
            else None
        ),
    }


def endpoint_with_inventory(
    db: Session,
    endpoint: Endpoint,
) -> dict:
    result = endpoint_to_dict(endpoint)

    inventory = db.scalar(
        select(NetworkInventory).where(
            NetworkInventory.endpoint_id
            == endpoint.id
        )
    )

    if inventory:
        result["inventory"] = {
            "status": inventory.status,
            "summary": json.loads(
                inventory.summary_json or "{}"
            ),
            "scanned_at": (
                inventory.scanned_at.isoformat()
                if inventory.scanned_at
                else None
            ),
            "last_error": inventory.last_error,
        }
    else:
        result["inventory"] = {
            "status": "NOT_SCANNED",
            "summary": {},
            "scanned_at": None,
            "last_error": None,
        }

    return result


def queue_inventory_refresh(
    db: Session,
    user: User,
    endpoint: Endpoint,
) -> Job:
    active = db.scalar(
        select(Job).where(
            Job.endpoint_id == endpoint.id,
            Job.job_type == "ENDPOINT_INVENTORY",
            Job.status.in_(
                {
                    "QUEUED",
                    "RUNNING",
                    "RETRY",
                }
            ),
        )
    )

    if active:
        return active

    inventory = db.scalar(
        select(NetworkInventory).where(
            NetworkInventory.endpoint_id
            == endpoint.id
        )
    )

    if inventory is None:
        inventory = NetworkInventory(
            endpoint_id=endpoint.id,
            status="QUEUED",
            summary_json="{}",
            inventory_json="{}",
        )
        db.add(inventory)
    else:
        inventory.status = "QUEUED"
        inventory.last_error = None
        inventory.updated_at = datetime.utcnow()

    job = Job(
        owner_user_id=user.id,
        endpoint_id=endpoint.id,
        job_type="ENDPOINT_INVENTORY",
        status="QUEUED",
        progress=0,
        current_step="inventory_queue",
    )

    db.add(job)
    db.flush()

    db.add(
        JobEvent(
            job_id=job.id,
            level="INFO",
            step="inventory_queue",
            public_message=(
                "Network inventory scan queued."
            ),
        )
    )

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="NETWORK_INVENTORY_REFRESHED",
            target_type="ENDPOINT",
            target_id=str(endpoint.id),
            details=(
                f"Inventory scan queued for "
                f"{endpoint.name}"
            ),
        )
    )

    db.commit()

    try:
        redis_client.rpush(
            "netauto:jobs",
            json.dumps(
                {
                    "id": job.id,
                    "type": job.job_type,
                }
            ),
        )
    except Exception as exc:
        job.status = "FAILED"
        job.error_message = "JOB_QUEUE_UNAVAILABLE"
        inventory.status = "ERROR"
        inventory.last_error = "JOB_QUEUE_UNAVAILABLE"
        db.commit()

        raise HTTPException(
            status_code=503,
            detail="JOB_QUEUE_UNAVAILABLE",
        ) from exc

    return job


@router.get(
    "/endpoints/{endpoint_id}/inventory"
)
def read_endpoint_inventory(
    endpoint_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    endpoint = get_accessible_endpoint(
        db,
        user,
        endpoint_id,
    )

    inventory = db.scalar(
        select(NetworkInventory).where(
            NetworkInventory.endpoint_id
            == endpoint.id
        )
    )

    if inventory is None:
        return {
            "endpoint": endpoint_to_dict(endpoint),
            "status": "NOT_SCANNED",
            "summary": {},
            "data": {},
            "last_error": None,
            "scanned_at": None,
        }

    technical = user.role in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }

    result = inventory_to_dict(
        inventory,
        technical=technical,
    )

    result["endpoint"] = endpoint_to_dict(
        endpoint
    )

    return result


@router.post(
    "/endpoints/{endpoint_id}/inventory/refresh"
)
def refresh_endpoint_inventory(
    endpoint_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    endpoint = get_accessible_endpoint(
        db,
        user,
        endpoint_id,
    )

    if endpoint.status != "READY":
        raise HTTPException(
            status_code=409,
            detail="ENDPOINT_MUST_BE_READY",
        )

    job = queue_inventory_refresh(
        db,
        user,
        endpoint,
    )

    return {
        "status": "queued",
        "endpoint_id": endpoint.id,
        "job_id": job.id,
    }


def collect_used_networks(
    inventories: list[NetworkInventory],
) -> list:
    used = []

    for record in inventories:
        try:
            data = json.loads(
                record.inventory_json or "{}"
            )
        except Exception:
            continue

        resources = data.get(
            "resources",
            {},
        )

        for value in resources.get(
            "cidrs",
            [],
        ):
            try:
                used.append(
                    ipaddress.ip_network(
                        value,
                        strict=False,
                    )
                )
            except ValueError:
                continue

    return used


def suggest_free_cidr(
    inventories: list[NetworkInventory],
    version: int = 4,
) -> str | None:
    used = collect_used_networks(inventories)

    if version == 6:
        pool = ipaddress.ip_network(
            "fd77:77::/112"
        )
        prefix = 126
    else:
        pool = ipaddress.ip_network(
            "10.77.0.0/16"
        )
        prefix = 30

    for index, subnet in enumerate(
        pool.subnets(
            new_prefix=prefix,
        )
    ):
        if index > 16384:
            break

        if not any(
            subnet.overlaps(existing)
            for existing in used
            if existing.version
            == subnet.version
        ):
            return str(subnet)

    return None


def suggest_free_port(
    inventories: list[NetworkInventory],
    protocol: str,
) -> int | None:
    used = set()

    for record in inventories:
        try:
            data = json.loads(
                record.inventory_json or "{}"
            )
        except Exception:
            continue

        for item in (
            data.get("resources", {})
            .get("ports", [])
        ):
            if (
                str(item.get("protocol", "")).lower()
                == protocol.lower()
            ):
                try:
                    used.add(int(item["port"]))
                except Exception:
                    pass

    for port in list(
        range(51820, 51921)
    ) + list(
        range(40000, 40101)
    ):
        if port not in used:
            return port

    return None


@router.post("/inventory/conflicts")
def check_inventory_conflicts(
    payload: InventoryConflictRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    endpoints = []

    for endpoint_id in payload.endpoint_ids:
        endpoints.append(
            get_accessible_endpoint(
                db,
                user,
                endpoint_id,
            )
        )

    records = list(
        db.scalars(
            select(NetworkInventory).where(
                NetworkInventory.endpoint_id.in_(
                    [item.id for item in endpoints]
                )
            )
        ).all()
    )

    missing = [
        item.id
        for item in endpoints
        if not any(
            record.endpoint_id == item.id
            and record.status == "READY"
            for record in records
        )
    ]

    if missing:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "INVENTORY_REQUIRED",
                "endpoint_ids": missing,
            },
        )

    conflicts = []

    candidate_network = None

    if payload.candidate_cidr:
        try:
            candidate_network = ipaddress.ip_network(
                payload.candidate_cidr,
                strict=False,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="INVALID_CIDR",
            ) from exc

    for endpoint in endpoints:
        record = next(
            item
            for item in records
            if item.endpoint_id == endpoint.id
        )

        try:
            data = json.loads(
                record.inventory_json or "{}"
            )
        except Exception:
            data = {}

        resources = data.get(
            "resources",
            {},
        )

        if candidate_network:
            for existing in resources.get(
                "cidrs",
                [],
            ):
                try:
                    existing_network = (
                        ipaddress.ip_network(
                            existing,
                            strict=False,
                        )
                    )
                except ValueError:
                    continue

                if (
                    existing_network.version
                    == candidate_network.version
                    and existing_network.overlaps(
                        candidate_network
                    )
                ):
                    conflicts.append(
                        {
                            "endpoint_id": endpoint.id,
                            "endpoint_name": endpoint.name,
                            "type": "CIDR",
                            "requested": str(
                                candidate_network
                            ),
                            "existing": str(
                                existing_network
                            ),
                        }
                    )

        if (
            payload.interface_name
            and payload.interface_name
            in resources.get(
                "interface_names",
                [],
            )
        ):
            conflicts.append(
                {
                    "endpoint_id": endpoint.id,
                    "endpoint_name": endpoint.name,
                    "type": "INTERFACE_NAME",
                    "requested": (
                        payload.interface_name
                    ),
                }
            )

        if payload.port and payload.protocol:
            for port_item in resources.get(
                "ports",
                [],
            ):
                if (
                    int(port_item.get("port", 0))
                    == payload.port
                    and str(
                        port_item.get(
                            "protocol",
                            "",
                        )
                    ).lower()
                    == payload.protocol.lower()
                ):
                    conflicts.append(
                        {
                            "endpoint_id": endpoint.id,
                            "endpoint_name": endpoint.name,
                            "type": "PORT",
                            "requested": (
                                f"{payload.protocol.lower()}"
                                f"/{payload.port}"
                            ),
                            "existing": port_item,
                        }
                    )

        if (
            payload.vxlan_vni
            and payload.vxlan_vni
            in resources.get(
                "vxlan_vnis",
                [],
            )
        ):
            conflicts.append(
                {
                    "endpoint_id": endpoint.id,
                    "endpoint_name": endpoint.name,
                    "type": "VXLAN_VNI",
                    "requested": payload.vxlan_vni,
                }
            )

        if payload.tunnel_key:
            existing_keys = [
                str(item.get("key"))
                for item in resources.get(
                    "tunnel_keys",
                    [],
                )
            ]

            if str(payload.tunnel_key) in existing_keys:
                conflicts.append(
                    {
                        "endpoint_id": endpoint.id,
                        "endpoint_name": endpoint.name,
                        "type": "TUNNEL_KEY",
                        "requested": payload.tunnel_key,
                    }
                )

    protocol = (
        payload.protocol or "udp"
    ).lower()

    return {
        "safe": not conflicts,
        "conflicts": conflicts,
        "suggestions": {
            "cidr": suggest_free_cidr(
                records,
                version=(
                    candidate_network.version
                    if candidate_network
                    else 4
                ),
            ),
            "port": suggest_free_port(
                records,
                protocol,
            ),
            "interface_name": next(
                (
                    f"netauto{index}"
                    for index in range(100)
                    if all(
                        f"netauto{index}"
                        not in json.loads(
                            record.inventory_json
                            or "{}"
                        ).get(
                            "resources",
                            {},
                        ).get(
                            "interface_names",
                            [],
                        )
                        for record in records
                    )
                ),
                None,
            ),
        },
    }


@router.get(
    "/bot/endpoints/{telegram_id}/{endpoint_id}/inventory",
    dependencies=[Depends(require_bot_key)],
)
def read_bot_endpoint_inventory(
    telegram_id: int,
    endpoint_id: int,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        telegram_id,
        db,
    )

    endpoint = get_accessible_endpoint(
        db,
        user,
        endpoint_id,
    )

    inventory = db.scalar(
        select(NetworkInventory).where(
            NetworkInventory.endpoint_id
            == endpoint.id
        )
    )

    if inventory is None:
        return {
            "endpoint": endpoint_to_dict(endpoint),
            "status": "NOT_SCANNED",
            "summary": {},
            "data": {},
            "scanned_at": None,
        }

    technical = user.role in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }

    result = inventory_to_dict(
        inventory,
        technical=technical,
    )

    result["endpoint"] = endpoint_to_dict(
        endpoint
    )

    return result


@router.post(
    "/bot/endpoints/{telegram_id}/{endpoint_id}/inventory/refresh",
    dependencies=[Depends(require_bot_key)],
)
def refresh_bot_endpoint_inventory(
    telegram_id: int,
    endpoint_id: int,
    db: Session = Depends(get_db),
):
    user = linked_telegram_user(
        telegram_id,
        db,
    )

    endpoint = get_accessible_endpoint(
        db,
        user,
        endpoint_id,
    )

    if endpoint.status != "READY":
        raise HTTPException(
            status_code=409,
            detail="ENDPOINT_MUST_BE_READY",
        )

    job = queue_inventory_refresh(
        db,
        user,
        endpoint,
    )

    return {
        "status": "queued",
        "endpoint_id": endpoint.id,
        "job_id": job.id,
    }




def serialize_precheck_result(
    db: Session,
    precheck: PairPrecheck,
) -> dict:
    endpoint_a = db.get(
        Endpoint,
        precheck.endpoint_a_id,
    )

    endpoint_b = db.get(
        Endpoint,
        precheck.endpoint_b_id,
    )

    job = db.get(
        Job,
        precheck.job_id,
    )

    try:
        result = json.loads(
            precheck.result_json or "{}"
        )
    except Exception:
        result = {}

    status = precheck.status

    if job and job.status == "FAILED":
        status = "FAILED"

    elif job and job.status == "RUNNING":
        status = "RUNNING"

    elif job and job.status == "QUEUED":
        status = "QUEUED"

    return {
        "id": precheck.id,
        "job_id": precheck.job_id,
        "status": status,
        "job_status": (
            job.status
            if job
            else None
        ),
        "job_error": (
            job.error_message
            if job
            else None
        ),
        "endpoint_a": (
            {
                "id": endpoint_a.id,
                "name": endpoint_a.name,
                "host": endpoint_a.host,
            }
            if endpoint_a
            else None
        ),
        "endpoint_b": (
            {
                "id": endpoint_b.id,
                "name": endpoint_b.name,
                "host": endpoint_b.host,
            }
            if endpoint_b
            else None
        ),
        "result": result,
        "created_at": (
            precheck.created_at.isoformat()
            if precheck.created_at
            else None
        ),
        "finished_at": (
            precheck.finished_at.isoformat()
            if precheck.finished_at
            else None
        ),
    }


@router.get("/precheck-results")
def list_precheck_results(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(PairPrecheck)

    if user.role not in {
        UserRole.ADMIN,
        UserRole.SUPER_ADMIN,
    }:
        query = query.where(
            PairPrecheck.owner_user_id
            == user.id
        )

    records = db.scalars(
        query
        .order_by(PairPrecheck.id.desc())
        .limit(50)
    ).all()

    return {
        "items": [
            serialize_precheck_result(
                db,
                item,
            )
            for item in records
        ]
    }


@router.get(
    "/precheck-result/{precheck_id}"
)
def read_persistent_precheck_result(
    precheck_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    precheck = db.get(
        PairPrecheck,
        precheck_id,
    )

    if not precheck:
        raise HTTPException(
            status_code=404,
            detail="PRECHECK_NOT_FOUND",
        )

    if (
        user.role not in {
            UserRole.ADMIN,
            UserRole.SUPER_ADMIN,
        }
        and precheck.owner_user_id
        != user.id
    ):
        raise HTTPException(
            status_code=403,
            detail="PRECHECK_ACCESS_DENIED",
        )

    return serialize_precheck_result(
        db,
        precheck,
    )
