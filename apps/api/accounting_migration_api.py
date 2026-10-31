from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from apps.api.accounts_api import AccountSafeRoute
from core.security import audit_from_user, require_role


class EmptyMigrationRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')


def create_accounting_migration_router(service):
    router=APIRouter(prefix='/api/billing/owner/workspaces/{workspace_id}/accounting-migrations',
                     route_class=AccountSafeRoute,dependencies=[Depends(require_role('SUPER_ADMIN'))])

    @router.get('')
    def listing(workspace_id:str):
        return {'routes':service.routes(workspace_id),'operations':service.history(workspace_id)}

    @router.post('/routes/{route_id}/preflight')
    def preflight(workspace_id:str,route_id:str,body:EmptyMigrationRequest,user=Depends(require_role('SUPER_ADMIN'))):
        return service.preflight(workspace_id,route_id,audit_from_user(user))

    @router.get('/{operation_id}')
    def status(workspace_id:str,operation_id:str):
        return service.status(workspace_id,operation_id)

    @router.post('/{operation_id}/execute',status_code=202)
    def execute(workspace_id:str,operation_id:str,body:EmptyMigrationRequest):
        return service.execute(workspace_id,operation_id)

    return router
