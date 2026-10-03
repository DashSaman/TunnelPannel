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
