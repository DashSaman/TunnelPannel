"""Owner-only allowance grants; route credentials authorize only credit messages."""
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from apps.api.accounts_api import AccountSafeRoute
from core.security import RateLimiter, current_user, require_role


class AllowanceGrant(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    quota_bytes: int = Field(strict=True, ge=1, le=10**16)
    ends_at: float = Field(ge=0)
    expected_revision: int = Field(strict=True, ge=0)
    new_period: bool = Field(default=False, strict=True)


class CreditMessage(BaseModel):
    model_config = ConfigDict(extra='forbid')
    request_id: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{1,64}$')
    amount: int = Field(default=0, strict=True, ge=0, le=8*1024*1024)
    period_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{32}$')
    grant_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{32}$')
    upload: int | None = Field(default=None, strict=True, ge=0, le=8*1024*1024)
    download: int | None = Field(default=None, strict=True, ge=0, le=8*1024*1024)
    close: bool = Field(default=False, strict=True)


def create_monthly_router(store, hooks, subscriptions):
    router = APIRouter(route_class=AccountSafeRoute, tags=['shared traffic allowance'])
    limiter = RateLimiter(default_limit=2000, default_window_s=10)

    @router.get('/api/billing/traffic')
    def customer_status(user=Depends(current_user)):
        return store.status(user['workspace_id'])

    @router.get('/api/billing/owner/workspaces/{workspace_id}/traffic', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def owner_status(workspace_id: str):
        return {**store.status(workspace_id), 'coverage':hooks.coverage(workspace_id)}

    @router.put('/api/billing/owner/workspaces/{workspace_id}/traffic')
    def owner_grant(workspace_id: str, body: AllowanceGrant, user=Depends(require_role('SUPER_ADMIN'))):
        lease = hooks.lease(workspace_id)
        if not lease.acquire(10):
            raise HTTPException(409, 'customer route admission is busy')
        try:
            coverage = hooks.coverage(workspace_id)
            if coverage['unmetered_routes']:
                raise HTTPException(409, 'active unmetered routes prevent complete shared accounting; explicit owner migration is required')
            hooks.callback_url()
            try:
                store.grant(workspace_id, body.quota_bytes, body.ends_at,
                            expected_revision=body.expected_revision, new_period=body.new_period,
                            actor=user.get('account_id') or user['token_hash'])
            except ValueError as error:
                raise HTTPException(409, str(error)) from None
            return {**store.status(workspace_id), 'coverage':coverage}
        finally:
            lease.release()

    @router.post('/quota/credits')
    def credit(body: CreditMessage, request: Request):
        auth = request.headers.get('authorization', '')
        token = auth[7:] if auth.startswith('Bearer ') else ''
        try:
            workspace = store.token_workspace(token)
            active = True
            if workspace != 'system':
                active = hooks.registry.scope_for(workspace) is not None and (
                    subscriptions.status(workspace)['can_start_work'] or store.preserves_existing(token))
                if not active and body.request_id:
                    raise HTTPException(403, 'customer traffic entitlement is inactive')
            if not limiter.allow((hashlib.sha256(token.encode()).hexdigest(),))[0]:
                raise HTTPException(429, 'credit request rate exceeded')
            result = store.exchange(token, **body.model_dump())
            if not active:
                result['ttl_s'] = 0
                result['period_id'] = None
            return result
        except PermissionError:
            raise HTTPException(401, 'route credential required') from None
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    return router
