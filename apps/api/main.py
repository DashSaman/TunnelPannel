"""Canonical application entrypoint (P13).

Serves: benchmark API, failover API, ranking + topology web UI, health,
status, active alerts and optional Prometheus metrics. One process, one
canonical core — no independent networking logic anywhere in the app
layer. Production install runs this under systemd (see install.sh).

    uvicorn apps.api.main:app --host 127.0.0.1 --port 8080
"""
from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from apps.api.benchmark_api import create_router as bench_router
from apps.api.failover_api import create_router as failover_router
from apps.web.web_api import create_web_router as web_router
from core.models import Alert, Base, BenchmarkSample, FailoverGroup, Node
from core.security import audit_from_user, rate_limit, record_audit, require_role

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////var/lib/tunnelpannel/tunnelpannel.db")

_shared_engine = None
_shared_factory = None


def _session_factory():
    global _shared_engine, _shared_factory
    if _shared_factory is None:
        _shared_engine = create_engine(DATABASE_URL, connect_args=(
            {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}))
        _shared_factory = sessionmaker(bind=_shared_engine)
    return _shared_factory


def caps_from_dict(p: dict):
    from orchestrator.benchmarking import NodeCaps
    return NodeCaps(node_id=p["node_id"], binaries=set(p.get("binaries", [])),
                    kernel_modules=set(p.get("kernel_modules", [])),
                    privileged=p.get("privileged", True),
                    os=p.get("os", "linux"), arch=p.get("arch", "amd64"))


def demo_adapter_factory(cand):
    """Wired to real engine adapters at deployment time (P5 adapters +
    SSH executors); refuses to fake results by default."""
    raise HTTPException(501, "benchmark execution requires engine executor wiring")


def create_app() -> FastAPI:
    global session_factory
    session_factory = _session_factory()
    app = FastAPI(title="TunnelPannel", version="0.1.0")
    Base.metadata.create_all(session_factory.kw["bind"])  # dev convenience; installer runs alembic

    app.include_router(bench_router(session_factory, caps_from_dict,
                                    demo_adapter_factory))
    app.include_router(failover_router(session_factory))
    app.include_router(web_router(session_factory))

    @app.get("/health")
    def health():
        with session_factory() as s:
            s.execute(select(func.count()).select_from(Node))
        return {"ok": True}

    @app.get("/api/status")
    def status():
        with session_factory() as s:
            groups = s.query(FailoverGroup).count()
            samples = s.query(BenchmarkSample).count()
            nodes = s.query(Node).count()
            active_alerts = s.query(Alert).filter(
                Alert.resolved_at.is_(None)).count()
            return {"mode": "auto", "active": None,
                    "up": samples, "total": samples,
                    "nodes": nodes, "failover_groups": groups,
                    "active_alerts": active_alerts}

    @app.get("/api/alerts/active")
    def active_alerts():
        with session_factory() as s:
            rows = s.query(Alert).filter(Alert.resolved_at.is_(None)).all()
            return [{"kind": a.kind, "severity": a.severity,
                     "key": a.context.get("key", ""), "raised_at": a.raised_at,
                     "occurrences": a.context.get("occurrences", 1)}
                    for a in rows]

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        from orchestrator.observability import prometheus_export
        with session_factory() as s:
            m = {"nodes_total": s.query(Node).count(),
                 "benchmark_samples_total": s.query(BenchmarkSample).count(),
                 "failover_groups_total": s.query(FailoverGroup).count(),
                 "alerts_active": s.query(Alert).filter(
                     Alert.resolved_at.is_(None)).count()}
        return prometheus_export(m)

    @app.post("/api/admin/reload")
    def admin_reload(user=Depends(rate_limit("admin", limit=6, window_s=60.0)),
                     _role=Depends(require_role("OPERATOR", "SUPER_ADMIN"))):
        record_audit(session_factory, audit_from_user(user), "admin.reload")
        return {"reloaded": True, "by": user}

    @app.get("/api/admin/overview")
    def admin_overview(user=Depends(require_role("VIEWER"))):
        return {"overview": "ok", "for": user}

    @app.get("/api/whoami")
    def whoami(user=Depends(require_role("VIEWER"))):
        return user

    return app


app = create_app()
