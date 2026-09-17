"""TunnelGuard — security: password hashing, JWT, credential encryption.

- Passwords: PBKDF2-HMAC-SHA256 (stdlib, 200k iterations, per-user salt).
- Sessions:  JWT HS256 signed with the persistent master secret.
- Peer SSH credentials: Fernet (AES128-CBC+HMAC) derived from master secret,
  stored encrypted in the `tunnels.remote_ssh` column. Never logged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time

import jwt as pyjwt
from cryptography.fernet import Fernet, InvalidToken

from . import config

_ITERATIONS = 200_000


def _master() -> bytes:
    return config.load_secret_key()


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- JWT
def create_token(username: str, role: str = "admin") -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + config.JWT_TTL_HOURS * 3600,
    }
    return pyjwt.encode(payload, _master(), algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, _master(), algorithms=[config.JWT_ALGORITHM])
    except pyjwt.PyJWTError:
        return None


# ---------------------------------------------------------------- Fernet
def _fernet() -> Fernet:
    raw = _master()
    # master is urlsafe-b64 already (generated that way) — normalize anyway
    try:
        return Fernet(raw)
    except (ValueError, TypeError):
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


def encrypt_creds(data: dict) -> str:
    import json

    return _fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_creds(blob: str) -> dict:
    import json

    if not blob:
        return {}
    try:
        return json.loads(_fernet().decrypt(blob.encode()))
    except (InvalidToken, ValueError, TypeError):
        return {}
