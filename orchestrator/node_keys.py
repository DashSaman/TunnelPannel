"""Crash-recoverable, exact-line SSH key bootstrap and rotation."""
import base64
import datetime as dt
import json
from pathlib import Path
import shlex
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from core.models import Job, Node, SecretReference
from core.workspaces import freeze_factory
from orchestrator.host_lease import HostLease
from orchestrator.remote_nodes import NodeRemote, encrypt_credentials, node_access


def change_authorized_key(remote, *, add=None, remove=None):
    source = Path(__file__).with_name('authorized_keys.py').read_text(encoding='utf-8')
    payload = base64.b64encode(json.dumps({'username':remote.endpoint['ssh_username'],
                                          'add':add, 'remove':remove}).encode()).decode()
    remote.run('python3 -c '+shlex.quote(source)+' '+shlex.quote(payload), root=True, timeout=30)


def _finish(factory, identity):
    """Retry only exact owned additions/removals recorded before mutation."""
    with factory() as session:
        job = session.get(Job, identity)
        node = session.get(Node, job.payload['node_id'])
        endpoint, credentials = node_access(session, node.id)
        committed = node.secret_ref == job.payload['new_secret_id']
        remove = job.payload.get('old_public_line') if committed else job.payload['new_public_line']
    remote = NodeRemote(endpoint, credentials).connect()
    try:
        if remove:
            change_authorized_key(remote, remove=remove)
        with factory() as session:
            job = session.get(Job, identity)
            obsolete = job.payload['old_secret_id'] if committed else job.payload['new_secret_id']
            if not session.query(Node).filter_by(secret_ref=obsolete).count():
                secret = session.get(SecretReference, obsolete)
                if secret:
                    session.delete(secret)
            job.state = 'PASS' if committed else 'FAILED'
            job.error = None if committed else 'new key was not committed; exact owned addition rolled back'
            job.finished_at = dt.datetime.now(dt.timezone.utc)
            session.commit()
    finally:
        remote.close()


def provision_managed_key(factory, node_id):
    factory = freeze_factory(factory)
    with factory() as session:
        try:
            endpoint, old = node_access(session, node_id)
        except ValueError:
            raise HTTPException(404, 'node access not found') from None
    lease = HostLease(endpoint)
    if not lease.acquire(0):
        raise HTTPException(409, 'physical node is busy; retry after current operation')
    remote, identity = None, None
    try:
        with factory() as session:
            pending = session.query(Job).filter_by(kind='node_key', state='APPLYING').all()
            if any(j.payload.get('node_id') == node_id for j in pending):
                raise HTTPException(409, 'previous key operation needs recovery first')
            # Refresh after taking the physical host lease.
            endpoint, old = node_access(session, node_id)
            node = session.get(Node, node_id)
            private = Ed25519PrivateKey.generate()
            pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                        serialization.NoEncryption()).decode()
            public = private.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                       serialization.PublicFormat.OpenSSH).decode()
            line = 'restrict '+public+' tp-managed-'+uuid.uuid4().hex
            credentials = {'auth_method':'KEY', 'secret':pem, 'sudo_mode':old.get('sudo_mode','NOPASSWD'),
                           'managed_public_line':line}
            secret = SecretReference(kind='ssh_managed', ciphertext=encrypt_credentials(credentials))
            session.add(secret)
            session.flush()
            job = Job(kind='node_key', state='APPLYING', payload={'node_id':node_id,
                'old_secret_id':node.secret_ref, 'new_secret_id':secret.id, 'new_public_line':line,
                'old_public_line':old.get('managed_public_line')})
            session.add(job)
            session.commit()
            identity, new_secret_id, old_secret_id = job.id, secret.id, node.secret_ref
        remote = NodeRemote(endpoint, old).connect()
        change_authorized_key(remote, add=line)
        check = NodeRemote(endpoint, credentials).connect()
        try:
            if check.run('id -u', root=True)['stdout'].strip() != '0':
                raise ValueError('new key lacks required deployment privilege')
        finally:
            check.close()
        with factory() as session:
            if session.bind.dialect.name == 'sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            node = session.get(Node, node_id)
            if (node.secret_ref != old_secret_id or node.host != endpoint['host']
                    or node.ssh_port != endpoint['port'] or node.ssh_username != endpoint['ssh_username']
                    or node.host_key_fingerprint != endpoint['host_key_fingerprint']):
                raise ValueError('node credentials changed concurrently')
            node.secret_ref, node.auth_type = new_secret_id, 'key'
            session.commit()
        _finish(factory, identity)
        return {'node_id':node_id, 'job_id':identity, 'managed':True, 'password_retained':False,
                'privilege':'the SSH account retains its deployment privileges; root keys are root access'}
    except HTTPException:
        raise
    except Exception:
        if identity:
            try:
                _finish(factory, identity)
            except Exception:
                pass  # durable APPLYING row retains encrypted recovery material
        raise HTTPException(400, 'managed key operation failed; previous access or durable recovery is preserved') from None
    finally:
        if remote:
            remote.close()
        lease.release()


def revoke_managed_key(factory, node_id, replacement, *, lease_held=False):
    """Verify replacement access before revoking the exact owned key."""
    factory = freeze_factory(factory)
    with factory() as session:
        endpoint, old = node_access(session, node_id)
        old_id = session.get(Node, node_id).secret_ref
    if not old.get('managed_public_line'):
        raise HTTPException(409, 'node has no managed key to revoke')
    if replacement.get('secret') == old['secret']:
        raise HTTPException(400, 'replacement access must use a different credential')
    lease = HostLease(endpoint)
    if not lease_held and not lease.acquire(0):
        raise HTTPException(409, 'physical node is busy')
    remote, identity = None, None
    try:
        remote = NodeRemote(endpoint, replacement).connect()
        if remote.run('id -u', root=True)['stdout'].strip() != '0':
            raise ValueError('replacement lacks deployment privilege')
        with factory() as session:
            if session.bind.dialect.name == 'sqlite':
                from sqlalchemy import text
                session.execute(text('BEGIN IMMEDIATE'))
            node = session.get(Node, node_id)
            if node.secret_ref != old_id:
                raise ValueError('credentials changed concurrently')
            secret = SecretReference(kind='ssh_key' if replacement['auth_method']=='KEY' else 'ssh_password',
                                     ciphertext=encrypt_credentials(replacement))
            session.add(secret)
            session.flush()
            job = Job(kind='node_key', state='APPLYING', payload={'node_id':node_id,
                'old_secret_id':old_id, 'new_secret_id':secret.id, 'new_public_line':None,
                'old_public_line':old['managed_public_line']})
            session.add(job)
            node.secret_ref, node.auth_type = secret.id, 'key' if replacement['auth_method']=='KEY' else 'password'
            session.commit()
            identity = job.id
        _finish(factory, identity)
        return {'node_id':node_id, 'revoked':True, 'replacement_verified':True}
    except Exception:
        raise HTTPException(400, 'managed key revocation failed; access or durable cleanup is preserved') from None
    finally:
        if remote:
            remote.close()
        if not lease_held:
            lease.release()


def recover_managed_keys(factory):
    with factory() as session:
        jobs = [(j.id,j.payload['node_id']) for j in session.query(Job).filter_by(kind='node_key',state='APPLYING')]
    for identity, node_id in jobs:
        try:
            with factory() as session:
                endpoint, _ = node_access(session, node_id)
            lease = HostLease(endpoint)
            if lease.acquire(0):
                try:
                    _finish(factory, identity)
                finally:
                    lease.release()
        except Exception:
            import logging
            logging.getLogger(__name__).error('Managed key recovery deferred')
