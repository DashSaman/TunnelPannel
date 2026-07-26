from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.admin_router import router as admin_router
from app.bot_control_router import router as bot_control_router
from app.composer_router import router as composer_router
from app.config import get_settings
from app.db import Base, SessionLocal, engine, get_db
from app.endpoint_router import current_user, router as endpoint_router
from app.execution_router import router as execution_router
from app.models import AuditLog, User, UserRole
from app.schemas import ChangePasswordRequest, LoginRequest, TokenResponse
from app.security import create_access_token, hash_password, verify_password

settings = get_settings()
API_VERSION = "1.0.0"
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def validate_runtime_configuration() -> None:
    problems: list[str] = []

    if len(settings.app_secret_key) < 32:
        problems.append("APP_SECRET_KEY must contain at least 32 characters")

    if len(settings.jwt_secret_key) < 32:
        problems.append("JWT_SECRET_KEY must contain at least 32 characters")

    if settings.telegram_bot_enabled and not settings.telegram_bot_token:
        problems.append("TELEGRAM_BOT_TOKEN is required while the bot is enabled")

    if settings.telegram_bot_enabled and not settings.bot_internal_api_key:
        problems.append("BOT_INTERNAL_API_KEY is required while the bot is enabled")

    if problems:
        raise RuntimeError("; ".join(problems))


def bootstrap_database() -> None:
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        existing = db.scalar(
            select(User).where(User.username == settings.bootstrap_admin_username)
        )

        if existing:
            return

        if not settings.bootstrap_admin_password:
            raise RuntimeError(
                "BOOTSTRAP_ADMIN_PASSWORD is required only for the first startup"
            )

        admin = User(
            username=settings.bootstrap_admin_username,
            email=settings.bootstrap_admin_email or None,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role=UserRole.SUPER_ADMIN,
            is_active=True,
            email_verified=bool(settings.bootstrap_admin_email),
            telegram_2fa_required=True,
            must_change_password=True,
            created_at=utcnow(),
        )

        db.add(admin)
        db.add(
            AuditLog(
                actor_user_id=None,
                action="BOOTSTRAP_SUPER_ADMIN_CREATED",
                target_type="USER",
                target_id=None,
                details=json.dumps({"username": admin.username}),
                created_at=utcnow(),
            )
        )
        db.commit()


def request_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    if forwarded:
        return forwarded[:100]
    return request.client.host[:100] if request.client else "unknown"


def login_rate_key(request: Request, username: str) -> str:
    client = request_client_ip(request)
    normalized = username.strip().lower()[:100]
    return f"netauto:login-rate:{client}:{normalized}"


def assert_login_rate(request: Request, username: str) -> str:
    key = login_rate_key(request, username)

    try:
        attempts = redis_client.incr(key)
        if attempts == 1:
            redis_client.expire(key, 900)
        if attempts > 10:
            raise HTTPException(status_code=429, detail="LOGIN_RATE_LIMITED")
    except HTTPException:
        raise
    except Exception:
        # Authentication remains available if Redis is temporarily unavailable.
        pass

    return key


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_runtime_configuration()
    bootstrap_database()
    yield


app = FastAPI(
    title=f"{settings.app_name} API",
    version=API_VERSION,
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"

    return response


app.include_router(endpoint_router)
app.include_router(composer_router)
app.include_router(execution_router)
app.include_router(bot_control_router)
app.include_router(admin_router)


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "service": "netauto-api",
        "version": API_VERSION,
        "environment": settings.app_env,
        "billing_mode": settings.billing_mode,
        "payments_enabled": settings.payments_enabled,
    }


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    rate_key = assert_login_rate(request, payload.username)
    user = db.scalar(select(User).where(User.username == payload.username.strip()))

    if not user or not verify_password(payload.password, user.password_hash):
        db.add(
            AuditLog(
                actor_user_id=user.id if user else None,
                action="AUTH_LOGIN_FAILED",
                target_type="USER",
                target_id=str(user.id) if user else None,
                details=json.dumps(
                    {
                        "username": payload.username.strip()[:100],
                        "client": request_client_ip(request),
                    },
                    ensure_ascii=False,
                ),
                created_at=utcnow(),
            )
        )
        db.commit()
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="ACCOUNT_INACTIVE")

    try:
        redis_client.delete(rate_key)
    except Exception:
        pass

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="AUTH_LOGIN_SUCCEEDED",
            target_type="USER",
            target_id=str(user.id),
            details=None,
            created_at=utcnow(),
        )
    )
    db.commit()

    token = create_access_token(str(user.id), user.role.value)

    return TokenResponse(
        access_token=token,
        must_change_password=user.must_change_password,
        role=user.role.value,
    )


@app.post("/api/v1/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="CURRENT_PASSWORD_INVALID")

    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="NEW_PASSWORD_MUST_BE_DIFFERENT")

    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False

    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="AUTH_PASSWORD_CHANGED",
            target_type="USER",
            target_id=str(user.id),
            details="Password changed by account owner",
            created_at=utcnow(),
        )
    )
    db.commit()

    return {
        "status": "ok",
        "message": "PASSWORD_CHANGED",
        "reauthenticate": True,
    }


@app.get("/api/v1/auth/me")
def auth_me(user: User = Depends(current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "telegram_id": user.telegram_id,
        "telegram_2fa_required": user.telegram_2fa_required,
        "must_change_password": user.must_change_password,
    }
