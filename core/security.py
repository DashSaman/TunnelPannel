"""Canonical RBAC (P13 §33) — roles enforced by the BACKEND, not the UI.

SUPER_ADMIN: everything · OPERATOR: operate networking · VIEWER: read-only
(no networking mutation). Auth header carries a static API token whose
role mapping lives in configuration (env in dev, runtime config in prod);
production deployments front this with the panel session layer.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import HTTPException, Request

SUPER_ADMIN, OPERATOR, VIEWER = "SUPER_ADMIN", "OPERATOR", "VIEWER"
ROLES = (SUPER_ADMIN, OPERATOR, VIEWER)

# permission -> roles allowed
PERMISSIONS: dict[str, set[str]] = {
    "view": {SUPER_ADMIN, OPERATOR, VIEWER},
    "operate_network": {SUPER_ADMIN, OPERATOR},
    "benchmark": {SUPER_ADMIN, OPERATOR},
    "configure": {SUPER_ADMIN, OPERATOR},
    "manage_users": {SUPER_ADMIN},
    "manage_security": {SUPER_ADMIN},
    "maintenance": {SUPER_ADMIN, OPERATOR},
}


def allowed(role: str, permission: str) -> bool:
    return role in PERMISSIONS.get(permission, set())


class ViewerOnly:
    """Marker for viewer-scoped dependencies."""


def _role_for_token(token: str) -> str | None:
    """Token → role from TP_RBAC_TOKENS config "role:hash,role:hash".
    Tokens are stored as SHA-256 hashes; comparison is constant-time."""
    raw = os.environ.get("TP_RBAC_TOKENS", "")
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        role, _, digest = entry.partition(":")
        if role in ROLES and digest:
            expected = bytes.fromhex(digest)
            got = hashlib.sha256(token.encode()).digest()
            if hmac.compare_digest(expected, got):
                return role
    return None


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=403, detail="not authorized for this action")


def current_user(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="authentication required")
    role = _role_for_token(token)
    if role is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"role": role, "token_hash": hashlib.sha256(token.encode()).hexdigest()[:12]}


def require_role(*roles: str):
    """FastAPI dependency enforcing membership in `roles` (backend-side)."""
    allowed_roles = set(roles)

    def dep(request: Request) -> dict:
        user = current_user(request)
        if user["role"] not in allowed_roles:
            raise _unauthorized()
        return user

    return dep


# ── audit trail (P13 §33) ──────────────────────────────────────────────

def record_audit(session_factory, actor: str, action: str,
                 target: str | None = None, detail: dict | None = None) -> None:
    """Persist a security-sensitive mutation to the audit log.
    Actor is a redacted identity (role + token hash), never a raw token."""
    from core.models import AuditLog
    with session_factory() as session:
        session.add(AuditLog(actor=actor, action=action, target=target,
                             detail=detail or {}))
        session.commit()


def audit_from_user(user: dict) -> str:
    return f"{user['role']}:{user['token_hash']}"


# ── rate limiting (P13 §33) ────────────────────────────────────────────

import threading
import time as _time


class _Window:
    def __init__(self):
        self.hits: list[float] = []


class RateLimiter:
    """In-process sliding-window limiter keyed by (identity, bucket)."""

    def __init__(self, default_limit: int = 60, default_window_s: float = 60.0):
        self.default_limit = default_limit
        self.default_window_s = default_window_s
        self._windows: dict[tuple, _Window] = {}
        self._lock = threading.Lock()

    def allow(self, key: tuple, limit: int | None = None,
              window_s: float | None = None) -> tuple[bool, float]:
        """Returns (allowed, retry_after_s)."""
        limit = limit or self.default_limit
        window_s = window_s or self.default_window_s
        now = _time.monotonic()
        with self._lock:
            w = self._windows.setdefault(key, _Window())
            w.hits = [t for t in w.hits if now - t < window_s]
            if len(w.hits) >= limit:
                retry = window_s - (now - w.hits[0])
                return False, max(retry, 0.0)
            w.hits.append(now)
            return True, 0.0


_limiters: dict[str, RateLimiter] = {}
_limiters_lock = threading.Lock()


def rate_limit(bucket: str, limit: int | None = None, window_s: float | None = None):
    """FastAPI dependency: sliding-window rate limit per authenticated
    identity. Active by default (60 req/min); disabled only by explicit
    TP_RATE_LIMIT=0 for local development."""
    import os

    def dep(request: Request) -> dict:
        user = current_user(request)
        disabled = os.environ.get("TP_RATE_LIMIT", "1") == "0"
        if not disabled:
            with _limiters_lock:
                limiter = _limiters.setdefault(bucket, RateLimiter())
            key = (bucket, user["token_hash"])
            allowed, retry = limiter.allow(key, limit, window_s)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail=f"rate limit exceeded for {bucket}; retry in {retry:.0f}s")
        return user
    return dep
