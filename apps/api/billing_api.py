"""Explicit sandbox entitlements and a bounded signed external-event bridge."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from apps.api.accounts_api import AccountSafeRoute
from core.manual_commerce import CommercialPlan, ManualPayment
from core.security import current_user, require_role


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    plan: str = Field(min_length=1,max_length=48,pattern=r'^[a-z][a-z0-9_-]*$')


class SandboxGrant(PlanRequest):
    days: int = Field(default=30, ge=1, le=366)
    grace_hours: int = Field(default=24, ge=0, le=168)


class ExpiryPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    stop_on_expiry: bool = Field(strict=True)


def create_billing_router(store):
    router = APIRouter(tags=['subscriptions'], route_class=AccountSafeRoute)

    @router.get('/billing/plans')
    def public_plans():
        return store.plans()

    @router.get('/api/billing/status')
    def status(user=Depends(current_user)):
        return store.status(user['workspace_id'])

    @router.get('/api/billing/plans', dependencies=[Depends(current_user)])
    def plans():
        return store.plans()

    @router.post('/api/billing/requests', status_code=201)
    def request_plan(body: PlanRequest, user=Depends(require_role('SUPER_ADMIN'))):
        return store.request_plan(user['workspace_id'], body.plan)

    @router.get('/api/billing/requests')
    def requests(user=Depends(current_user)):
        return store.requests(user['workspace_id'])

    @router.get('/api/billing/workspaces', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def workspaces():
        return [{**workspace, 'subscription': store.status(workspace['id'])} for workspace in store.registry.list()]

    @router.get('/api/billing/owner/requests', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def owner_requests():
        return store.requests()

    @router.get('/api/billing/owner/plans', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def owner_plans():
        return store.commercial_plans(include_disabled=True)

    @router.put('/api/billing/owner/plans/{plan_id}', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def save_plan(plan_id: str, body: CommercialPlan):
        return store.save_plan(plan_id, body.model_dump())

    @router.get('/api/billing/owner/payments', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def owner_payments():
        return store.manual_payments()

    @router.get('/api/billing/payments')
    def customer_payments(user=Depends(current_user)):
        return store.manual_payments(user['workspace_id'])

    @router.post('/api/billing/owner/workspaces/{workspace_id}/payments', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def record_payment(workspace_id: str, body: ManualPayment, user=Depends(current_user)):
        return store.record_manual_payment(workspace_id, body.model_dump(), actor=user.get('account_id') or user['token_hash'])

    @router.post('/api/billing/workspaces/{workspace_id}/policy')
    def policy(workspace_id: str, body: ExpiryPolicy, _=Depends(require_role('SUPER_ADMIN'))):
        return store.set_policy(workspace_id, stop_on_expiry=body.stop_on_expiry)

    @router.post('/api/billing/workspaces/{workspace_id}/sandbox-grant')
    def grant(workspace_id: str, body: SandboxGrant, _=Depends(require_role('SUPER_ADMIN'))):
        return store.sandbox_grant(workspace_id, body.plan, days=body.days, grace_hours=body.grace_hours)

    @router.post('/billing/events')
    async def events(request: Request):
        if request.headers.get('content-type', '').split(';', 1)[0] != 'application/json':
            raise HTTPException(415, 'application/json required')
        body, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 16384:
                raise HTTPException(413, 'billing payload too large')
            body.append(chunk)
        return store.apply_event(b''.join(body), request.headers.get('x-tp-timestamp', ''),
                                 request.headers.get('x-tp-signature', ''))

    @router.post('/api/billing/workspaces/{workspace_id}/sandbox-cancel')
    def cancel(workspace_id:str,_=Depends(require_role('SUPER_ADMIN'))):
        return store.sandbox_cancel(workspace_id)

    return router
