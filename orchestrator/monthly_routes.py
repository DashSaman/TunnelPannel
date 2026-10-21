"""Monthly-pool admission and retirement of explicitly owned route workers."""
import json
import os
from pathlib import Path
import re
import shlex

from fastapi import HTTPException

from core.models import Job, SecretReference
from core.workspaces import workspace_context
from orchestrator.host_lease import HostLease
from orchestrator.monthly_client import validate_url
from orchestrator.remote_nodes import NodeRemote, decrypt_credentials, encrypt_credentials, node_access


class MonthlyRoutes:
    def __init__(self, store, registry, default_factory):
        self.store, self.registry, self.default_factory = store, registry, default_factory

    def identity(self):
        return (workspace_context.get() or {}).get('id', 'system')

    def lease(self, workspace):
        return HostLease({'host':'monthly-admission:' + str(Path(self.store.path).resolve()) + ':' + workspace})

    def factory(self, workspace):
        if workspace == 'system':
            return self.default_factory
        if not any(row['id'] == workspace for row in self.registry.list()):
            raise HTTPException(404, 'customer workspace not found')
        return self.registry._factory(workspace)

    def callback_url(self):
        try:
            return validate_url(os.environ.get('TP_MONTHLY_QUOTA_URL', ''))
        except ValueError:
            raise HTTPException(503, 'configure TP_MONTHLY_QUOTA_URL on this execution controller first') from None

    def coverage(self, workspace):
        with self.factory(workspace)() as session:
            jobs = session.query(Job).filter(Job.kind=='mesh_route',
                Job.state.in_(['APPLYING','COMMITTED','DEGRADED','STOPPING'])).all()
            return {'managed_routes':sum(bool(j.payload.get('monthly_secret_id')) for j in jobs),
                    'unmetered_routes':[j.id for j in jobs if not j.payload.get('monthly_secret_id')]}

    def attach(self, session, job, workspace):
        job.payload = {**job.payload, 'workspace_id':workspace}
        if not self.store.status(workspace)['period']:
            return
        url = self.callback_url()
        token = self.store.register_route(workspace, job.id)
        secret = SecretReference(kind='monthly_route', ciphertext=encrypt_credentials({'url':url,'token':token}))
        session.add(secret)
        session.flush()
        job.payload = {**job.payload, 'monthly_secret_id':secret.id}

    def config(self, session, job):
        identity = job.payload.get('monthly_secret_id')
        if not identity:
            return None
        secret = session.get(SecretReference, identity)
        if secret is None:
            raise RuntimeError('monthly route credential is missing')
        return decrypt_credentials(secret.ciphertext)

    def retire(self, factory, route_id):
        from orchestrator.mesh_routes import route_job, route_private
        with factory() as session:
            job = route_job(session, route_id)
            if not job.payload.get('monthly_secret_id') or not job.payload.get('runtime_secret_id'):
                return
            runtime = route_private(session, job)
            if not runtime['config'].get('monthly'):
                return  # newly enrolled credential has never run in this historical worker
            endpoint, credentials = node_access(session, job.payload['source'])
        path = runtime['config'].get('usage_path')
        if not re.fullmatch(r'[0-9a-f]{32}', route_id) or path != '/var/lib/tunnelpannel/route-usage/' + route_id + '.sqlite3':
            raise RuntimeError('monthly ledger ownership mismatch')
        remote = NodeRemote(endpoint, credentials).connect()
        try:
            stopped = remote.run('systemctl show --property=MainPID --value ' + shlex.quote(runtime['service']+'.service'),
                                 root=True, check=False)
            if stopped['stdout'].strip() not in {'','0'}:
                raise RuntimeError('cannot return credits before worker is stopped')
            if not self.store.has_open_credits(route_id):
                self.store.retire_route(route_id, {})
                return
            code = ('import sqlite3,json,pathlib; p=pathlib.Path(' + repr(path) + '); '
                    'assert p.is_file() and not p.is_symlink(); '
                    'db=sqlite3.connect(p.as_uri()+"?mode=ro",uri=True); '
                    'assert db.execute("PRAGMA integrity_check").fetchone()[0]=="ok"; '
                    'print(json.dumps({r[0]:[r[1],r[2]] for r in db.execute("SELECT id,upload,download FROM monthly_local")}))')
            result = remote.run('python3 -c ' + shlex.quote(code), root=True)
            self.store.retire_route(route_id, json.loads(result['stdout']))
        finally:
            remote.close()

    def renew(self, factory, route_id):
        from orchestrator.mesh_routes import route_job
        with factory() as session:
            job = route_job(session, route_id)
            if not job.payload.get('monthly_secret_id'):
                return
            config = self.config(session, job)
            try:
                self.store.token_workspace(config['token'])
                return
            except PermissionError:
                pass
            token = self.store.register_route(job.payload['workspace_id'], route_id)
            secret = session.get(SecretReference, job.payload['monthly_secret_id'])
            secret.ciphertext = encrypt_credentials({**config, 'token':token})
            session.commit()
