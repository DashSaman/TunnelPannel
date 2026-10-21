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
                  "max_active_routes": 24, "max_daily_candidate_units": 25000,
                  "max_route_mbps": 100000, "max_route_bytes": 10**16, "max_route_connections": 10000}


def validated_limits(current=None, changes=None):
    from core.traffic import TRAFFIC_CEILINGS
    configured = {**DEFAULT_LIMITS, **(current or {}), **(changes or {})}
    if set(configured) != set(DEFAULT_LIMITS) or any(
            not isinstance(v, int) or isinstance(v, bool) or v < 1
            or v > TRAFFIC_CEILINGS.get(k, 1000000 if k == 'max_daily_candidate_units' else 1000)
            for k, v in configured.items()):
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

    def scope_for(self, workspace_id):
        """Resolve a server-authenticated account identity, never a client header."""
        if not re.fullmatch(r'[0-9a-f]{32}', workspace_id):
            return None
        with self._connect() as connection:
            row = connection.execute('SELECT * FROM workspaces WHERE id=? AND enabled=1',
                                     (workspace_id,)).fetchone()
        if row is None:
            return None
        return {'id': row['id'], 'factory': self._factory(row['id']),
                'limits': {**DEFAULT_LIMITS, **json.loads(row['limits'])}}

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
    from core.accounts import AccountStore
    from apps.api.accounts_api import COOKIE_NAME, session_origin, verify_cookie_mutation
    app.state.accounts = accounts = AccountStore(registry)
    from core.subscriptions import SubscriptionStore
    app.state.subscriptions = subscriptions = SubscriptionStore(registry)

    @app.middleware("http")
    async def boundary(request, call_next):
        path = request.url.path
        protected = (path.startswith(("/api/", "/benchmarks", "/failover", '/auth/mfa/'))
                     or path in {'/metrics', '/auth/session', '/auth/logout', '/auth/password'})
        if not protected:
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        key = auth[7:].strip() if auth.startswith("Bearer ") else ""
        role = _role_for_token(key) if key else None
        account = None
        session_token = request.cookies.get(COOKIE_NAME, '') if not key else ''
        if session_token:
            account = accounts.authenticate_session(session_token)
            role = account['role'] if account else None
        system_scope = {'id': 'system', 'factory': scoped_factory.default, 'limits': DEFAULT_LIMITS}
        if session_token:
            scope = (system_scope if account['workspace_id'] == 'system' else
                     registry.scope_for(account['workspace_id'])) if account else None
        else:
            scope = system_scope if role else registry.authenticate(key)
        if scope is None:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        if account:
            try:
                session_origin(request)
                if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
                    verify_cookie_mutation(request, session_token)
            except HTTPException as error:
                return JSONResponse({'detail': error.detail}, status_code=error.status_code)
        request.state.principal = {"role": role or "SUPER_ADMIN", "workspace_id": scope["id"],
                                   "token_hash": hashlib.sha256((key or session_token).encode()).hexdigest()[:12]}
        if account:
            request.state.principal['account_id'] = account['id']
        # The owner registry is never delegated, even to a customer SUPER_ADMIN.
        if path.startswith(("/api/workspaces", '/api/accounts', '/api/billing/workspaces', '/api/billing/owner')) and (scope["id"] != "system" or role != "SUPER_ADMIN"):
            return JSONResponse({"detail": "owner access required"}, status_code=403)
        # Legacy UI mutation endpoints lacked their own role dependencies.
        if (request.method not in ("GET", "HEAD", "OPTIONS") and role == "VIEWER"
                and not path.startswith('/auth/') and path != '/api/mesh/estimate'):
            return JSONResponse({"detail": "not authorized for this action: read-only role"}, status_code=403)
        if scope['id'] != 'system':
            try:
                subscriptions.authorize_operation(scope['id'], request.method, path)
                scope['limits'] = subscriptions.status(scope['id'], scope['limits'])['limits']
            except HTTPException as error:
                return JSONResponse({'detail': error.detail}, status_code=error.status_code)
        context_token = workspace_context.set(scope)
        try:
            response = await call_next(request)
            response.headers['Cache-Control']='no-store'
            if request.method not in {'GET','HEAD','OPTIONS'} and response.status_code<400:
                # Static route pattern and hashed principal only. Never record bodies,
                # query strings, credentials, raw responses or untrusted URL fragments.
                from core.security import audit_from_user, record_audit
                pattern=getattr(request.scope.get('route'),'path','')
                if pattern:
                    try:
                        record_audit(scope['factory'],audit_from_user(request.state.principal),
                            ('http.'+request.method+'.'+pattern)[:64])
                    except Exception:
                        import logging
                        logging.getLogger(__name__).error('Scoped audit write unavailable')
            return response
        finally:
            workspace_context.reset(context_token)

    return registry
