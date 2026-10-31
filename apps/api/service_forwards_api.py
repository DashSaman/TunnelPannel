"""Tenant-scoped TCP services; existing auth, admission and route accounting."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from starlette.concurrency import run_in_threadpool

from core.models import Job
from core.security import require_role
from core.service_forwards import ForwardApplyUpdate, ForwardCreate, ForwardPreflight, service_job, service_public
from core.workspaces import scope_limits
from orchestrator.mesh_routes import route_job, route_private

ServiceID = Annotated[str, Path(pattern=r'^[0-9a-f]{32}$')]


def create_service_forwards_router(factory, service):
    router = APIRouter(prefix='/api/mesh/services', tags=['managed TCP services'],
        dependencies=[Depends(require_role('VIEWER', 'OPERATOR', 'SUPER_ADMIN'))])
    operator = Depends(require_role('OPERATOR', 'SUPER_ADMIN'))

    def accepted(identity):
        with factory() as session:
            job = service_job(session, identity)
            return {'id': job.id, 'state': job.state}

    @router.get('')
    def history():
        with factory() as session:
            return [service_public(job) for job in session.query(Job).filter_by(kind='mesh_service_forward')
                    .order_by(Job.created_at.desc()).limit(100)]

    @router.post('/preflight')
    def preflight(body: ForwardPreflight, _=operator):
        return service.preflight(factory, body, scope_limits())

    @router.post('', status_code=202)
    def create(body: ForwardCreate, _=operator):
        return accepted(service.create(factory, body, scope_limits()))

    @router.get('/{service_id}')
    def detail(service_id: ServiceID):
        result = service.observe(factory, service_id)
        with factory() as session:
            job = service_job(session, service_id)
            parent = route_job(session, job.payload['route_id'])
            config = route_private(session, parent)['config']
            traffic = config.get('traffic') or {}
            inherited = {'route_id': parent.id, 'mode': config.get('mode', 'failover'),
                'shared_customer_usage': bool(config.get('monthly')), 'rate_mbps': traffic.get('rate_mbps', 0),
                'route_quota_bytes': traffic.get('quota_bytes', 0),
                'max_connections': traffic.get('max_connections', 256),
                'target_health': 'listener checked at preflight; application not measured',
                'session_recovery': 'new connections use route failover; existing TCP sessions reconnect'}
        return {**result, 'inherited': inherited}

    @router.put('/{service_id}', status_code=202)
    def update(service_id: ServiceID, body: ForwardApplyUpdate, _=operator):
        return accepted(service.update(factory, service_id, body, scope_limits()))

    @router.post('/{service_id}/reconcile', status_code=202)
    def reconcile(service_id: ServiceID, body: ForwardApplyUpdate, _=operator):
        return accepted(service.reconcile(factory, service_id, body, scope_limits()))

    @router.delete('/{service_id}', status_code=202)
    async def stop(service_id: ServiceID, request: Request, _=operator):
        if await request.body():
            raise HTTPException(422, 'owned service stop requires an empty body')
        def owned_stop():
            service.stop(factory, service_id)
            return accepted(service_id)
        return await run_in_threadpool(owned_stop)

    return router
