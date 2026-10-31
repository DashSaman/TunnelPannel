"""Scoped telemetry enrollment; identity ingestion exists only on the mTLS hub."""
from fastapi import APIRouter, Depends, HTTPException, Response

from apps.api.accounts_api import AccountSafeRoute
from core.models import Node
from core.security import audit_from_user, record_audit, require_role
from core.workspaces import workspace_context


def create_agent_router(factory, store):
    router=APIRouter(prefix='/api/nodes',tags=['restricted telemetry'],route_class=AccountSafeRoute)

    def identity(node_id):
        scope=workspace_context.get()
        if not scope or scope['id']=='system':
            raise HTTPException(400,'telemetry enrollment requires a customer workspace')
        with factory() as session:
            if session.get(Node,node_id) is None:
                raise HTTPException(404,'node not found')
        return scope['id']

    @router.get('/{node_id}/agent',dependencies=[Depends(require_role('SUPER_ADMIN','OPERATOR','VIEWER'))])
    def status(node_id:str):
        return store.status(identity(node_id),node_id)

    @router.post('/{node_id}/agent')
    def issue(node_id:str,response:Response,user=Depends(require_role('SUPER_ADMIN'))):
        import os
        from urllib.parse import urlsplit
        url=urlsplit(os.environ.get('TP_AGENT_HUB_URL',''))
        if (url.scheme!='https' or not url.hostname or url.username or url.password
                or url.query or url.fragment or url.path not in ('','/')):
            raise HTTPException(503,'configure a verified HTTPS telemetry hub origin before enrollment')
        result=store.issue(identity(node_id),node_id)
        record_audit(factory,audit_from_user(user),'agent.issue',node_id)
        response.headers['Cache-Control']='no-store'
        return result

    @router.delete('/{node_id}/agent')
    def revoke(node_id:str,user=Depends(require_role('SUPER_ADMIN'))):
        result=store.revoke(identity(node_id),node_id)
        record_audit(factory,audit_from_user(user),'agent.revoke',node_id)
        return result

    return router
