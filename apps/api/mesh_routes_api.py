from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from core.models import Job
from core.security import require_role
from core.workspaces import scope_limits
from orchestrator.mesh_routes import observe_route, route_job, route_private, route_public, update_route_policy


class DeployRoute(BaseModel):
    campaign_id: str
    route_id: str
    methods: list[str] | None = Field(default=None, max_length=100)
    listen_host: Literal['127.0.0.1', '::1'] = '127.0.0.1'


class RoutePolicyRequest(BaseModel):
    order: list[str] | None = None
    pin: str | None = None


class ReconcileRoute(BaseModel):
    methods: list[str] | None = Field(default=None, min_length=1, max_length=100)


def create_mesh_routes_router(factory, service):
    router = APIRouter(prefix='/api/mesh/routes', tags=['mesh routes'],
        dependencies=[Depends(require_role('VIEWER', 'OPERATOR', 'SUPER_ADMIN'))])

    @router.post('', status_code=202)
    def deploy(body: DeployRoute, _=Depends(require_role('OPERATOR', 'SUPER_ADMIN'))):
        return {'id': service.create(factory, body, scope_limits()), 'state': 'APPLYING'}

    @router.get('')
    def history():
        with factory() as session:
            return [route_public(job) for job in session.query(Job).filter_by(kind='mesh_route')
                    .order_by(Job.created_at.desc()).limit(100)]

    @router.get('/{route_id}')
    def detail(route_id: str):
        return observe_route(factory, route_id)

    @router.get('/{route_id}/outbound')
    def outbound(route_id: str, _=Depends(require_role('OPERATOR', 'SUPER_ADMIN'))):
        with factory() as session:
            config = route_private(session, route_job(session, route_id))['config']
            return {'type': 'socks', 'server': config['listen_host'], 'server_port': config['listen_port'],
                    'username': config['username'], 'password': config['password'],
                    'network': 'tcp', 'scope': 'run your proxy client on the source node'}

    @router.put('/{route_id}/policy')
    def policy(route_id: str, body: RoutePolicyRequest, _=Depends(require_role('OPERATOR', 'SUPER_ADMIN'))):
        return update_route_policy(factory, route_id, body.order, body.pin)

    @router.delete('/{route_id}', status_code=202)
    def stop(route_id: str, _=Depends(require_role('OPERATOR', 'SUPER_ADMIN'))):
        service.stop(factory, route_id)
        return {'id': route_id, 'state': 'STOPPING'}

    @router.post('/{route_id}/reconcile', status_code=202)
    def reconcile(route_id: str, body: ReconcileRoute, _=Depends(require_role('OPERATOR', 'SUPER_ADMIN'))):
        service.reconcile(factory, route_id, body.methods, scope_limits())
        return {'id': route_id, 'state': 'APPLYING'}

    return router
