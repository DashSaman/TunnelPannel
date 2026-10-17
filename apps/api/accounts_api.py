"""Session endpoints are invite-only; owner APIs never delegate tenant selection."""
import hmac
import ipaddress
import os
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from apps.api.nodes_api import CredentialSafeRoute
from core.accounts import SESSION_SECONDS, csrf_token
from core.security import current_user, require_role

COOKIE_NAME = 'tp_session'


class AccountSafeRoute(CredentialSafeRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def no_store(request):
            response = await handler(request)
            response.headers['Cache-Control'] = 'no-store'
            return response
        return no_store


def session_origin(request):
    configured = os.environ.get('TP_PUBLIC_ORIGIN', '').rstrip('/')
    if configured:
        parsed = urlsplit(configured)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment):
            raise HTTPException(503, 'session public origin must be a configured HTTPS origin')
        expected, secure = configured, True
        if request.headers.get('host', '').lower() != parsed.netloc.lower():
            raise HTTPException(403, 'session host is not the configured public host')
        if request.url.scheme != 'https':
            raise HTTPException(403, 'public sessions require HTTPS with a trusted proxy configuration')
    else:
        try:
            peer = ipaddress.ip_address(request.client.host)
            host = ipaddress.ip_address(request.url.hostname)
            local = peer.is_loopback and host.is_loopback
        except (ValueError, AttributeError):
            local = bool(request.client and request.client.host in {'127.0.0.1', '::1'}
                         and request.url.hostname == 'localhost')
        if not local:
            raise HTTPException(503, 'configure TP_PUBLIC_ORIGIN for public account sessions')
        expected, secure = str(request.base_url).rstrip('/'), request.url.scheme == 'https'
    origin = request.headers.get('origin')
    if (origin is not None and origin != expected) or request.headers.get('sec-fetch-site') == 'cross-site':
        raise HTTPException(403, 'session origin rejected')
    return expected, secure


def verify_cookie_mutation(request, token):
    session_origin(request)
    supplied = request.headers.get('x-csrf-token', '')
    if not supplied or not hmac.compare_digest(supplied, csrf_token(token)):
        raise HTTPException(403, 'session CSRF verification required')


class InviteRequest(BaseModel):
    workspace_id: str = Field(min_length=1, max_length=32)
    email: str = Field(min_length=3, max_length=254)
    role: Literal['SUPER_ADMIN', 'OPERATOR', 'VIEWER'] = 'SUPER_ADMIN'
    ttl_s: int = Field(default=86400, ge=60, le=604800)


class RegisterRequest(BaseModel):
    invitation: str = Field(min_length=20, max_length=200)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(max_length=256)
    otp: str = Field(default='', max_length=100)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class OTPRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=6, pattern=r'^\d{6}$')


class PasswordChange(PasswordRequest):
    new_password: str = Field(min_length=12, max_length=256)
    otp: str = Field(default='', max_length=100)


def create_account_router(store):
    router = APIRouter(tags=['accounts'], route_class=AccountSafeRoute)

    def account_identity(request: Request):
        user = current_user(request)
        if not user.get('account_id'):
            raise HTTPException(403, 'sign in with an account for this operation')
        return user['account_id']

    def auth_request(request):
        _, secure = session_origin(request)
        if request.headers.get('content-type', '').split(';', 1)[0] != 'application/json':
            raise HTTPException(415, 'application/json required')
        return secure

    @router.post('/api/accounts/invitations', status_code=201)
    def invite(body: InviteRequest, _=Depends(require_role('SUPER_ADMIN'))):
        return store.invite(body.workspace_id, body.email, role=body.role, ttl_s=body.ttl_s)

    @router.get('/api/accounts', dependencies=[Depends(require_role('SUPER_ADMIN'))])
    def listing():
        return store.list_accounts()

    @router.post('/auth/register', status_code=201)
    def register(body: RegisterRequest, request: Request, response: Response):
        auth_request(request)
        response.headers['Cache-Control'] = 'no-store'
        return store.register(body.invitation, body.email, body.password)

    @router.post('/auth/login')
    def login(body: LoginRequest, request: Request, response: Response):
        secure = auth_request(request)
        result = store.login(body.email, body.password, otp=body.otp,
                             peer=request.client.host if request.client else 'unknown')
        response.set_cookie(COOKIE_NAME, result['token'], max_age=SESSION_SECONDS,
                            httponly=True, secure=secure, samesite='strict', path='/')
        response.headers['Cache-Control'] = 'no-store'
        return {'account': result['account'], 'csrf': result['csrf']}

    @router.get('/auth/session')
    def session(request: Request, response: Response, user=Depends(current_user)):
        session_origin(request)
        response.headers['Cache-Control'] = 'no-store'
        token = request.cookies.get(COOKIE_NAME, '')
        return {'principal': user, 'account': store.authenticate_session(token) if token else None,
                'csrf': csrf_token(token) if user.get('account_id') else None}

    @router.post('/auth/logout')
    def logout(request: Request, response: Response, _=Depends(account_identity)):
        store.logout(request.cookies.get(COOKIE_NAME, ''))
        response.delete_cookie(COOKIE_NAME, path='/')
        response.headers['Cache-Control'] = 'no-store'
        return {'signed_out': True}

    @router.post('/auth/mfa/setup')
    def setup(body: PasswordRequest, account_id=Depends(account_identity)):
        return store.begin_totp(account_id, body.password)

    @router.post('/auth/mfa/enable')
    def enable(body: OTPRequest, account_id=Depends(account_identity)):
        return store.enable_totp(account_id, body.otp)

    @router.post('/auth/password')
    def password(body: PasswordChange, response: Response, account_id=Depends(account_identity)):
        store.change_password(account_id, body.password, body.new_password, body.otp)
        response.delete_cookie(COOKIE_NAME, path='/')
        return {'password_changed': True, 'sessions_revoked': True}

    return router
