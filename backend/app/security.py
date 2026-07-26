from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
settings = get_settings()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, role: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.jwt_expire_minutes
    )

    payload = {
        "sub": subject,
        "role": role,
        "exp": expires,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm="HS256",
    )


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=["HS256"],
        )
    except JWTError as exc:
        raise ValueError("INVALID_TOKEN") from exc


def _fernet():
    import base64
    import hashlib
    from cryptography.fernet import Fernet

    digest = hashlib.sha256(
        settings.app_secret_key.encode("utf-8")
    ).digest()

    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(
        value.encode("utf-8")
    ).decode("utf-8")


def decrypt_secret(value: str) -> str:
    return _fernet().decrypt(
        value.encode("utf-8")
    ).decode("utf-8")
