"""Node registration and discovery; credentials remain encrypted and private."""
import base64
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field, model_validator

from core.models import Node, NodeInventory, SecretReference
from core.security import rate_limit, require_role
from orchestrator.remote_nodes import discover, encrypt_credentials, node_access


class CredentialSafeRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def safe_handler(request):
            try:
                return await handler(request)
            except RequestValidationError as error:
                # Model-level errors otherwise echo the whole SSH credential body.
                detail = [{key: row[key] for key in ('loc', 'msg', 'type') if key in row}
                          for row in error.errors()]
                raise HTTPException(422, detail) from None
        return safe_handler


class NodeRegistration(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = "root"
    host_key_fingerprint: str
    password: str = ""
    private_key: str = ""

    @model_validator(mode="after")
    def validate_access(self):
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", self.host):
            raise ValueError("invalid host")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", self.ssh_username):
            raise ValueError("invalid SSH username")
        fingerprint = self.host_key_fingerprint
        if fingerprint.startswith("SHA256:"):
            try:
                assert len(base64.b64decode(fingerprint[7:] + "=" * (-len(fingerprint[7:]) % 4))) == 32
            except Exception:
                raise ValueError("invalid SHA256 fingerprint") from None
        elif not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
            raise ValueError("a pinned SHA256 host fingerprint is required")
        if bool(self.password) == bool(self.private_key):
            raise ValueError("provide exactly one password or private key")
        return self


class NodeOnboarding(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = "root"
    password: str = ""
    private_key: str = ""

    @model_validator(mode="after")
    def validate_access(self):
        NodeRegistration(**self.model_dump(), host_key_fingerprint="0" * 64)
        return self


class KeyReplacement(BaseModel):
    password: str = Field(default='',max_length=256)
    private_key: str = Field(default='',max_length=16384)

    @model_validator(mode='after')
    def exactly_one(self):
        if bool(self.password)==bool(self.private_key):
            raise ValueError('provide exactly one verified replacement credential')
        return self


def public_node(node):
    return {"id": node.id, "name": node.name, "host": node.host,
            "ssh_port": node.ssh_port, "ssh_username": node.ssh_username,
            "host_key_fingerprint": node.host_key_fingerprint}


def create_nodes_router(session_factory):
    router = APIRouter(prefix="/api/nodes", tags=["nodes"], route_class=CredentialSafeRoute)

    @router.get("", dependencies=[Depends(require_role("VIEWER", "OPERATOR", "SUPER_ADMIN"))])
    def list_nodes():
        with session_factory() as session:
            return [public_node(n) for n in session.query(Node).order_by(Node.name).all()]

    @router.post("", status_code=201)
    def register(body: NodeRegistration, _=Depends(require_role("SUPER_ADMIN"))):
        from core.workspaces import scope_limits, validate_customer_target
        validate_customer_target(body.host)
        credentials = {"auth_method": "PASSWORD" if body.password else "KEY",
                       "secret": body.password or body.private_key, "sudo_mode": "NOPASSWD"}
        try:
            ciphertext = encrypt_credentials(credentials)
        except ValueError as e:
            raise HTTPException(503, str(e)) from None
        with session_factory() as session:
            if session.bind.dialect.name == 'sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            if session.query(Node).count() >= scope_limits()["max_nodes"]:
                raise HTTPException(409, "workspace node limit reached")
            if session.query(Node).filter_by(name=body.name).first():
                raise HTTPException(409, "node name already exists")
            secret = SecretReference(kind="ssh_password" if body.password else "ssh_key",
                                     ciphertext=ciphertext)
            session.add(secret)
            session.flush()
            node = Node(name=body.name, host=body.host, ssh_port=body.ssh_port,
                        ssh_username=body.ssh_username, secret_ref=secret.id,
                        auth_type="password" if body.password else "key",
                        host_key_fingerprint=body.host_key_fingerprint)
            session.add(node)
            session.commit()
            return public_node(node)

    @router.post("/onboard", status_code=201)
    def onboard(body: NodeOnboarding, user=Depends(require_role("SUPER_ADMIN")),
                _limit=Depends(rate_limit('ssh_onboarding', limit=12))):
        from core.workspaces import scope_limits, validate_customer_target
        from orchestrator.remote_nodes import observe_host_key
        validate_customer_target(body.host)
        with session_factory() as session:
            if session.query(Node).count() >= scope_limits()['max_nodes']:
                raise HTTPException(409, 'workspace node limit reached')
        try:
            fingerprint = observe_host_key(body.host, body.ssh_port)
            registration = NodeRegistration(**body.model_dump(), host_key_fingerprint=fingerprint)
            # Authenticate and discover before persisting an unusable node.
            endpoint = {"id": "onboarding", "host": body.host, "port": body.ssh_port,
                        "ssh_username": body.ssh_username, "host_key_fingerprint": fingerprint}
            credentials = {"auth_method": "PASSWORD" if body.password else "KEY",
                           "secret": body.password or body.private_key, "sudo_mode": "NOPASSWD"}
            snapshot = discover(endpoint, credentials)
        except Exception:
            raise HTTPException(400, "SSH onboarding failed; verify address, credentials and root/sudo access") from None
        result = register(registration, user)
        with session_factory() as session:
            snapshot["node_id"] = result["id"]
            session.add(NodeInventory(node_id=result["id"], snapshot=snapshot, summary=snapshot))
            session.commit()
        return {**result, "trust_basis": "first observed SSH host key", "inventory": snapshot}

    @router.post("/{node_id}/discover")
    def inventory(node_id: str, _=Depends(require_role("SUPER_ADMIN", "OPERATOR"))):
        with session_factory() as session:
            try:
                endpoint, credentials = node_access(session, node_id)
                snapshot = discover(endpoint, credentials)
            except Exception as e:
                raise HTTPException(400, "node discovery failed: " + str(e)[:180]) from None
            session.add(NodeInventory(node_id=node_id, snapshot=snapshot, summary=snapshot))
            session.commit()
            return snapshot

    @router.put('/{node_id}')
    def update(node_id: str, body: NodeRegistration, _=Depends(require_role('SUPER_ADMIN'))):
        from orchestrator.host_lease import HostLease
        with session_factory() as session:
            node=session.get(Node,node_id)
            if node is None:
                raise HTTPException(404,'node not found')
            lease=HostLease({'host':node.host,'host_key_fingerprint':node.host_key_fingerprint})
        if not lease.acquire(0):
            raise HTTPException(409,'physical node is busy')
        try:
            return update_access(node_id,body)
        finally:
            lease.release()

    def update_access(node_id, body):
        credentials = {'auth_method': 'PASSWORD' if body.password else 'KEY',
                       'secret': body.password or body.private_key, 'sudo_mode': 'NOPASSWD'}
        with session_factory() as session:
            previous=session.get(Node,node_id)
            if previous is None:
                raise HTTPException(404,'node not found')
            from orchestrator.remote_nodes import decrypt_credentials
            old_secret=session.get(SecretReference,previous.secret_ref)
            managed=(old_secret and old_secret.kind=='ssh_managed'
                     and decrypt_credentials(old_secret.ciphertext).get('managed_public_line'))
            if managed and (body.host!=previous.host or body.ssh_port!=previous.ssh_port
                    or body.ssh_username!=previous.ssh_username or body.host_key_fingerprint!=previous.host_key_fingerprint):
                raise HTTPException(409,'revoke the managed key with verified replacement access before changing the endpoint')
        if managed:
            from orchestrator.node_keys import revoke_managed_key
            revoke_managed_key(session_factory,node_id,credentials,lease_held=True)
        try:
            ciphertext = encrypt_credentials(credentials)
        except ValueError as error:
            raise HTTPException(503, str(error)) from None
        with session_factory() as session:
            if session.bind.dialect.name=='sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            node = session.get(Node, node_id)
            if node is None:
                raise HTTPException(404, 'node not found')
            if body.host != node.host:
                raise HTTPException(400, 'register a separate node for a different host')
            other = session.query(Node).filter_by(name=body.name).first()
            if other and other.id != node.id:
                raise HTTPException(409, 'node name already exists')
            old_id=node.secret_ref
            secret = SecretReference(kind='ssh_password' if body.password else 'ssh_key', ciphertext=ciphertext)
            session.add(secret)
            session.flush()
            node.secret_ref=secret.id
            session.flush()
            if old_id and not session.query(Node).filter_by(secret_ref=old_id).count():
                obsolete=session.get(SecretReference,old_id)
                if obsolete:
                    session.delete(obsolete)
            node.name, node.ssh_port, node.ssh_username = body.name, body.ssh_port, body.ssh_username
            node.host_key_fingerprint = body.host_key_fingerprint
            node.auth_type = 'password' if body.password else 'key'
            session.query(NodeInventory).filter_by(node_id=node.id).delete()
            session.commit()
            return public_node(node)

    @router.post('/{node_id}/managed-key')
    def managed_key(node_id:str,user=Depends(rate_limit('managed_ssh_key',limit=6))):
        if user['role']!='SUPER_ADMIN':
            raise HTTPException(403,'administrator access required')
        from orchestrator.node_keys import provision_managed_key
        from core.security import audit_from_user, record_audit
        result=provision_managed_key(session_factory,node_id)
        record_audit(session_factory,audit_from_user(user),'node.managed_key.rotate',node_id)
        return result

    @router.post('/{node_id}/managed-key/revoke')
    def revoke_key(node_id:str,body:KeyReplacement,user=Depends(require_role('SUPER_ADMIN'))):
        from orchestrator.node_keys import revoke_managed_key
        from core.security import audit_from_user, record_audit
        credentials={'auth_method':'PASSWORD' if body.password else 'KEY',
                     'secret':body.password or body.private_key,'sudo_mode':'NOPASSWD'}
        result=revoke_managed_key(session_factory,node_id,credentials)
        record_audit(session_factory,audit_from_user(user),'node.managed_key.revoke',node_id)
        return result

    return router
