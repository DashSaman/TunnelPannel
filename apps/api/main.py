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
from apps.api.nodes_api import create_nodes_router
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


def create_app(factory=None) -> FastAPI:
    import asyncio
    from contextlib import asynccontextmanager, suppress
    import logging
    from pathlib import Path
    from core.workspaces import ScopedFactory, install_workspace_boundary
    from apps.api.workspaces_api import create_workspace_router
    session_factory = ScopedFactory(factory or _session_factory())
    # Compatibility for operator scripts; route closures retain this app's own
    # factory even if another app instance is constructed in the same process.
    globals()["session_factory"] = session_factory
    def recover_mesh():
        app.state.accounting_migrations.recover()
        factories = [session_factory.default]
        for workspace in registry.list():
            if workspace['enabled']:
                try:
                    factories.append(registry._factory(workspace['id']))
                except Exception as error:
                    logging.getLogger(__name__).error('Workspace recovery unavailable: %s', type(error).__name__)
        for scoped in factories:
            from orchestrator.node_keys import recover_managed_keys
            try:
                recover_managed_keys(scoped)
                app.state.benchmarks.recover(scoped)
                app.state.mesh_campaigns.recover(scoped)
                app.state.mesh_routes.recover(scoped)
                app.state.operations_monitor.tick(scoped)
            except Exception as error:
                logging.getLogger(__name__).error('Scoped recovery deferred: %s',type(error).__name__)
        # Opt-in expiry cleanup remains scoped even for disabled workspaces.
        from orchestrator.operations_monitor import expire_workspace_routes
        for item in app.state.subscriptions.expiry_candidates():
            try:
                scoped = registry._factory(item['workspace_id'])
                app.state.subscriptions.run_expiry_action(item['workspace_id'], item['revision'],
                    lambda: expire_workspace_routes(scoped, app.state.mesh_routes))
            except Exception as error:
                logging.getLogger(__name__).error('Expiry cleanup deferred: %s', type(error).__name__)

    @asynccontextmanager
    async def lifespan(application):
        await asyncio.to_thread(recover_mesh)
        async def recovery_loop():
            while True:
                await asyncio.sleep(30)
                try:
                    await asyncio.to_thread(recover_mesh)
                except Exception as error:
                    logging.getLogger(__name__).error('Mesh recovery deferred: %s', type(error).__name__)
        recovery = asyncio.create_task(recovery_loop())
        try:
            yield
        finally:
            recovery.cancel()
            with suppress(asyncio.CancelledError):
                await recovery

    app = FastAPI(title="TunnelPannel", version="0.1.0", lifespan=lifespan)
    Base.metadata.create_all(session_factory.kw["bind"])  # dev convenience; installer runs alembic
    directory = os.environ.get("TP_WORKSPACES_DIR") or str(
        Path(session_factory.kw["bind"].url.database or ".").parent / "workspaces")
    registry = install_workspace_boundary(app, session_factory, directory)
    from core.monthly_usage import MonthlyUsage
    from orchestrator.monthly_routes import MonthlyRoutes
    from apps.api.monthly_api import create_monthly_router
    app.state.monthly_usage = MonthlyUsage(registry.directory / 'registry.db')
    monthly_routes = MonthlyRoutes(app.state.monthly_usage, registry, session_factory.default)
    from orchestrator.admin_accounting import AdminAccounting
    from apps.api.accounting_migration_api import create_accounting_migration_router
    app.state.accounting_migrations=AdminAccounting(monthly_routes)
    app.include_router(create_accounting_migration_router(app.state.accounting_migrations))
    app.include_router(create_monthly_router(app.state.monthly_usage, monthly_routes, app.state.subscriptions))
    from apps.api.body_limit import BodyLimit
    app.add_middleware(BodyLimit, max_bytes=65536)
    app.include_router(create_workspace_router(registry))
    from apps.api.accounts_api import create_account_router
    app.include_router(create_account_router(app.state.accounts))
    from apps.api.billing_api import create_billing_router
    app.include_router(create_billing_router(app.state.subscriptions))

    from orchestrator.pair_runtime import prepare_benchmark
    app.include_router(create_nodes_router(session_factory))
    from apps.api.agent_api import create_agent_router
    from core.agent_identity import AgentIdentityStore
    app.state.agent_identities=AgentIdentityStore(registry)
    app.include_router(create_agent_router(session_factory,app.state.agent_identities))
    benchmarks = bench_router(session_factory, caps_from_dict, None,
                              prepare=prepare_benchmark(session_factory), secure=True)
    app.state.benchmarks = benchmarks.service
    app.include_router(benchmarks)
    app.include_router(failover_router(session_factory))
    app.include_router(web_router(session_factory))
    from apps.api.mesh_api import create_mesh_router
    from orchestrator.mesh_service import CampaignService
    app.state.mesh_campaigns = CampaignService()
    app.include_router(create_mesh_router(session_factory, app.state.mesh_campaigns))
    from apps.api.mesh_routes_api import create_mesh_routes_router
    from orchestrator.mesh_routes import RouteService
    app.state.mesh_routes = RouteService(monthly=monthly_routes)
    app.include_router(create_mesh_routes_router(session_factory, app.state.mesh_routes))
    from apps.api.operations_api import create_operations_router
    from orchestrator.operations_monitor import OperationsMonitor
    app.state.operations_monitor = OperationsMonitor()
    app.include_router(create_operations_router(session_factory))

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
    def admin_overview(user=Depends(require_role("VIEWER", "OPERATOR", "SUPER_ADMIN"))):
        return {"overview": "ok", "for": user}

    @app.get("/api/whoami")
    def whoami(user=Depends(require_role("VIEWER", "OPERATOR", "SUPER_ADMIN"))):
        return user

    return app


app = create_app()
