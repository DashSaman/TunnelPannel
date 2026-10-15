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
        credentials = {'auth_method': 'PASSWORD' if body.password else 'KEY',
                       'secret': body.password or body.private_key, 'sudo_mode': 'NOPASSWD'}
        try:
            ciphertext = encrypt_credentials(credentials)
        except ValueError as error:
            raise HTTPException(503, str(error)) from None
        with session_factory() as session:
            node = session.get(Node, node_id)
            if node is None:
                raise HTTPException(404, 'node not found')
            if body.host != node.host:
                raise HTTPException(400, 'register a separate node for a different host')
            other = session.query(Node).filter_by(name=body.name).first()
            if other and other.id != node.id:
                raise HTTPException(409, 'node name already exists')
            secret = session.get(SecretReference, node.secret_ref)
            if secret is None:
                secret = SecretReference(kind='ssh_password' if body.password else 'ssh_key',
                                         ciphertext=ciphertext)
                session.add(secret)
                session.flush()
                node.secret_ref = secret.id
            secret.ciphertext = ciphertext
            secret.kind = 'ssh_password' if body.password else 'ssh_key'
            node.name, node.ssh_port, node.ssh_username = body.name, body.ssh_port, body.ssh_username
            node.host_key_fingerprint = body.host_key_fingerprint
            node.auth_type = 'password' if body.password else 'key'
            session.query(NodeInventory).filter_by(node_id=node.id).delete()
            session.commit()
            return public_node(node)

    return router
