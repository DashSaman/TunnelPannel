"""Database-per-customer isolation and owner-managed, hashed workspace keys.

The context is set by authenticated ASGI middleware and copied by AnyIO into
sync handlers. Raw threads must call freeze() BEFORE dispatch.
"""
from __future__ import annotations

from contextvars import ContextVar
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import uuid

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

workspace_context: ContextVar[dict | None] = ContextVar("workspace", default=None)
DEFAULT_LIMITS = {"max_nodes": 12, "max_tunnels_per_route": 10,
                  "max_campaign_methods": 160, "max_active_campaigns": 1,
                  "max_active_routes": 24}


def validated_limits(current=None, changes=None):
    configured = {**DEFAULT_LIMITS, **(current or {}), **(changes or {})}
    if set(configured) != set(DEFAULT_LIMITS) or any(
            not isinstance(v, int) or isinstance(v, bool) or v < 1 or v > 1000
            for v in configured.values()):
        raise HTTPException(400, 'invalid workspace limits')
    return configured


class ScopedFactory:
    def __init__(self, default):
        self.default = default

    def freeze(self):
        scope = workspace_context.get()
        return scope["factory"] if scope else self.default

    @property
    def kw(self):
        return self.freeze().kw

    def __call__(self, *args, **kwargs):
        return self.freeze()(*args, **kwargs)


def freeze_factory(factory):
    return factory.freeze() if isinstance(factory, ScopedFactory) else factory


def scope_limits():
    scope = workspace_context.get()
    return dict((scope or {}).get("limits", DEFAULT_LIMITS))


def active_test_count(session):
    """A campaign and its active child occupy one shared admission slot."""
    from core.models import Job
    jobs = session.query(Job).filter(Job.kind.in_(['mesh_campaign', 'benchmark']),
        Job.state.in_(['QUEUED', 'RUNNING'])).all()
    return sum(job.kind == 'mesh_campaign' or not (job.payload or {}).get('campaign_id')
               for job in jobs)


def validate_customer_target(host: str):
    scope = workspace_context.get()
    if not scope or scope["id"] == "system":
        return
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global or address.is_multicast:
            raise ValueError()
    except ValueError:
        raise HTTPException(400, "customer SSH targets must be public IP addresses") from None


class WorkspaceRegistry:
    def __init__(self, directory):
        self.directory = Path(directory)
        self._lock = threading.RLock()
        self._factories = {}

    def _connect(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.directory / "registry.db", timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE IF NOT EXISTS workspaces "
                           "(id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT UNIQUE NOT NULL, "
                           "enabled INTEGER NOT NULL DEFAULT 1, limits TEXT NOT NULL)")
        if os.name != "nt":
            os.chmod(self.directory / "registry.db", 0o600)
        return connection

    def _factory(self, workspace_id):
        if not re.fullmatch(r"[0-9a-f]{32}", workspace_id):
            raise ValueError("invalid workspace identity")
        with self._lock:
            if workspace_id not in self._factories:
                from alembic import command
                from alembic.config import Config
                root = Path(__file__).resolve().parents[1]
                path = self.directory / (workspace_id + ".db")
                engine = create_engine("sqlite:///" + path.as_posix(),
                                       connect_args={"check_same_thread": False, "timeout": 30})
                config = Config(str(root / "alembic.ini"))
                config.set_main_option("script_location", str(root / "migrations"))
                from orchestrator.host_lease import HostLease
                lease = HostLease({'host': 'workspace-schema:' + str(self.directory.resolve())})
                if not lease.acquire(120):
                    raise HTTPException(503, 'workspace schema migration is busy')
                try:
                    with engine.begin() as connection:
                        config.attributes["connection"] = connection
                        command.upgrade(config, "head")
                finally:
                    lease.release()
                if os.name != "nt":
                    os.chmod(path, 0o600)
                self._factories[workspace_id] = sessionmaker(bind=engine)
            return self._factories[workspace_id]

    def create(self, name, limits=None):
        configured = validated_limits(changes=limits)
        workspace_id, key = uuid.uuid4().hex, "tpw_" + secrets.token_urlsafe(36)
        self._connect().close()
        self._factory(workspace_id)
        with self._connect() as connection:
            connection.execute("INSERT INTO workspaces(id,name,key_hash,limits) VALUES(?,?,?,?)",
                               (workspace_id, name, hashlib.sha256(key.encode()).hexdigest(),
                                json.dumps(configured)))
        return {"id": workspace_id, "name": name, "limits": configured, "api_key": key}

    def authenticate(self, key):
        if not key.startswith("tpw_") or len(key) > 200:
            return None
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM workspaces WHERE key_hash=? AND enabled=1",
                                     (hashlib.sha256(key.encode()).hexdigest(),)).fetchone()
        if row is None:
            return None
        return {"id": row["id"], "factory": self._factory(row["id"]),
                "limits": {**DEFAULT_LIMITS, **json.loads(row["limits"])}}

    def list(self):
        with self._connect() as connection:
            rows = connection.execute("SELECT id,name,enabled,limits FROM workspaces ORDER BY name").fetchall()
        return [{"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]),
                 "limits": json.loads(r["limits"])} for r in rows]

    def disable(self, workspace_id):
        with self._connect() as connection:
            cursor = connection.execute("UPDATE workspaces SET enabled=0 WHERE id=?", (workspace_id,))
            if not cursor.rowcount:
                raise HTTPException(404, "workspace not found")

    def update(self, workspace_id, *, name=None, limits=None, enabled=None):
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute('SELECT * FROM workspaces WHERE id=?', (workspace_id,)).fetchone()
            if row is None:
                raise HTTPException(404, 'workspace not found')
            configured = validated_limits(json.loads(row['limits']), limits)
            connection.execute('UPDATE workspaces SET name=?,limits=?,enabled=? WHERE id=?',
                (name if name is not None else row['name'], json.dumps(configured),
                 int(enabled) if enabled is not None else row['enabled'], workspace_id))
        return {'id': workspace_id, 'name': name if name is not None else row['name'],
                'limits': configured, 'enabled': enabled if enabled is not None else bool(row['enabled'])}

    def rotate_key(self, workspace_id):
        key = 'tpw_' + secrets.token_urlsafe(36)
        with self._connect() as connection:
            cursor = connection.execute('UPDATE workspaces SET key_hash=? WHERE id=?',
                (hashlib.sha256(key.encode()).hexdigest(), workspace_id))
            if not cursor.rowcount:
                raise HTTPException(404, 'workspace not found')
        return {'id': workspace_id, 'api_key': key}


def install_workspace_boundary(app, scoped_factory, directory):
    """Authenticate all data routes before selecting a database; HTML stays public."""
    from fastapi.responses import JSONResponse
    from core.security import _role_for_token
    registry = WorkspaceRegistry(directory)
    app.state.workspace_registry = registry

    @app.middleware("http")
    async def boundary(request, call_next):
        path = request.url.path
        protected = (path.startswith(("/api/", "/benchmarks", "/failover")) or path == "/metrics")
        if not protected:
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        key = auth[7:].strip() if auth.startswith("Bearer ") else ""
        role = _role_for_token(key) if key else None
        scope = ({"id": "system", "factory": scoped_factory.default,
                  "limits": DEFAULT_LIMITS} if role else registry.authenticate(key))
        if scope is None:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        request.state.principal = {"role": role or "SUPER_ADMIN", "workspace_id": scope["id"],
                                   "token_hash": hashlib.sha256(key.encode()).hexdigest()[:12]}
        # The owner registry is never delegated, even to a customer SUPER_ADMIN.
        if path.startswith("/api/workspaces") and (scope["id"] != "system" or role != "SUPER_ADMIN"):
            return JSONResponse({"detail": "owner access required"}, status_code=403)
        # Legacy UI mutation endpoints lacked their own role dependencies.
        if request.method not in ("GET", "HEAD", "OPTIONS") and role == "VIEWER":
            return JSONResponse({"detail": "not authorized for this action: read-only role"}, status_code=403)
        context_token = workspace_context.set(scope)
        try:
            return await call_next(request)
        finally:
            workspace_context.reset(context_token)

    return registry
