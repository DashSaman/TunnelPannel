"""Scoped operation history, opt-in monitoring and safe support export."""
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core.operations import OperationsStore
from core.models import AuditLog
from core.security import require_role


class MonitorPolicy(BaseModel):
    enabled: bool
    interval_s: int = Field(default=60, ge=60, le=3600)


def create_operations_router(factory):
    router = APIRouter(prefix='/api/operations', tags=['operations'],
        dependencies=[Depends(require_role('SUPER_ADMIN','OPERATOR','VIEWER'))])

    @router.get('/policy')
    def policy():
        return OperationsStore(factory).policy()

    @router.put('/policy')
    def configure(body: MonitorPolicy, _=Depends(require_role('SUPER_ADMIN','OPERATOR'))):
        return OperationsStore(factory).configure(body.enabled, body.interval_s)

    @router.get('/history')
    def history():
        return OperationsStore(factory).history()

    @router.get('/events')
    def events():
        return OperationsStore(factory).history('transition')

    @router.get('/audit')
    def audit():
        with factory() as session:
            return [{'at':r.ts,'action':r.action,'actor':r.actor,'target':r.target}
                    for r in session.query(AuditLog).order_by(AuditLog.ts.desc()).limit(100)]

    @router.get('/support')
    def support():
        return JSONResponse(OperationsStore(factory).support_export(), headers={
            'Cache-Control':'no-store', 'Content-Disposition':'attachment; filename="tunnelpannel-support.json"'})

    return router
