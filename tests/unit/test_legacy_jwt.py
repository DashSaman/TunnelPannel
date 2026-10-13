"""Legacy auth must preserve HS256 behavior without the vulnerable jose stack."""
import importlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest


@pytest.fixture
def security(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "backend"))
    for key in ("APP_SECRET_KEY", "JWT_SECRET_KEY", "DATABASE_URL", "REDIS_URL"):
        monkeypatch.setenv(key, "sqlite:///test.db" if key == "DATABASE_URL" else "test-setting")
    module = importlib.import_module("app.security")
    monkeypatch.setattr(module, "settings", SimpleNamespace(
        jwt_secret_key="legacy-auth-test-key-" * 4,
        jwt_expire_minutes=30))
    return module


def test_jwt_dependency_has_no_jose_or_ecdsa():
    req = (Path(__file__).resolve().parents[2] / "backend/requirements.txt").read_text()
    assert "python-jose" not in req
    assert "PyJWT" in req


def test_hs256_access_token_round_trip(security):
    token = security.create_access_token("user-1", "operator")
    claims = security.decode_access_token(token)
    assert claims["sub"] == "user-1"
    assert claims["role"] == "operator"
    assert claims["exp"] > datetime.now(timezone.utc).timestamp()


@pytest.mark.parametrize("kind", ["expired", "wrong-key", "wrong-algorithm", "malformed"])
def test_rejects_invalid_tokens(security, kind):
    payload = {"sub": "user-1", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    key = security.settings.jwt_secret_key
    algorithm = "HS256"
    if kind == "expired":
        payload["exp"] = datetime.now(timezone.utc) - timedelta(minutes=1)
    elif kind == "wrong-key":
        key = "different-test-key-with-at-least-32-bytes"
    elif kind == "wrong-algorithm":
        algorithm = "HS512"
    token = "invalid-token" if kind == "malformed" else jwt.encode(payload, key, algorithm=algorithm)
    with pytest.raises(ValueError, match="INVALID_TOKEN"):
        security.decode_access_token(token)
