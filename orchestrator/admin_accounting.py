"""System-owner tickets for the existing gateway-only accounting migration."""
import base64
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shlex
import sqlite3
import tempfile
import threading
import time

from fastapi import HTTPException
from sqlalchemy import select

from core.models import Job, SecretReference
from orchestrator.accounting_migration import migrate, validate_idle
from orchestrator.host_lease import HostLease
from orchestrator.mesh_routes import route_job, route_private
from orchestrator.remote_nodes import NodeRemote, decrypt_credentials, encrypt_credentials, node_access


def blocked(code):
    raise HTTPException(409, 'migration_'+code)


def payload_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


class AdminAccounting:
    def __init__(self,hooks):
        self.hooks=hooks
        self.factory=hooks.default_factory

    def lease(self,suffix):
        return HostLease({'host':'accounting-panel:'+str(Path(self.hooks.store.path).resolve())+':'+suffix})

    def routes(self,workspace):
        with self.hooks.factory(workspace)() as session:
            rows=session.scalars(select(Job).where(Job.kind=='mesh_route').order_by(Job.created_at.desc()).limit(100)).all()
            return [{'id':j.id,'state':j.state,'methods':j.payload.get('methods',[]),
                     'mode':j.payload.get('mode','failover'),
                     'accounting':'metered' if j.payload.get('monthly_secret_id') else 'pending' if j.payload.get('accounting_migration') else 'legacy',
                     'live':j.state in {'COMMITTED','DEGRADED'}} for j in rows]

    def inspect(self,workspace,identity):
        if not re.fullmatch(r'[0-9a-f]{32}',identity):
            raise HTTPException(404,'route not found')
        if workspace!='system' and self.hooks.registry.scope_for(workspace) is None:
            blocked('workspace_disabled')
        self.hooks.callback_url()
        period=self.hooks.store.status(workspace)['period']
        if period and not period['unlimited']:blocked('existing_ceiling')
        with self.hooks.factory(workspace)() as session:
            job=route_job(session,identity)
            if job.payload.get('monthly_secret_id'):blocked('already_metered')
            if job.state not in {'COMMITTED','DEGRADED'}:blocked('route_not_live')
            runtime=route_private(session,job);pending=job.payload.get('accounting_migration')
            expected=runtime['config']
            candidate=None
            if pending:
                if pending.get('phase')!='pending':blocked('intent_invalid')
                secret=session.get(SecretReference,pending['candidate_secret_id'])
                if not secret:blocked('intent_invalid')
                from orchestrator.accounting_migration import upgraded_config
                candidate=upgraded_config(identity,expected,decrypt_credentials(secret.ciphertext))
            fingerprint=payload_digest(job.payload)
            endpoint,credentials=node_access(session,job.payload['source'])
        directory=runtime['directory']
        if (directory!='/var/lib/tunnelpannel/mesh/'+identity+'/gateway'
                or not re.fullmatch(r'tpmesh-[0-9]+-0-gateway',runtime['service'])
                or expected.get('usage_path') not in {None,'/var/lib/tunnelpannel/route-usage/'+identity+'.sqlite3'}):
            blocked('ownership')
        code=('from pathlib import Path;import json,hashlib,subprocess; p=Path('+repr(directory)+'); '
              'assert not p.is_symlink() and not (p/"config.json").is_symlink(); '
              'raw=(p/"config.json").read_bytes(); '
              'pid=int(subprocess.check_output(["systemctl","show",'+repr(runtime['service'])+',"-p","MainPID","--value"],text=True)); '
              'assert pid>1 and str(p/"gateway.py").encode() in Path("/proc/"+str(pid)+"/cmdline").read_bytes(); '
              'print(json.dumps({"config":json.loads(raw),"state":json.loads((p/"state.json").read_text()),"pid":pid,"sha":hashlib.sha256(raw).hexdigest()}))')
        remote=NodeRemote(endpoint,credentials).connect()
        try:live=json.loads(remote.run('python3 -c '+shlex.quote(code),root=True,timeout=20)['stdout'])
        finally:remote.close()
        if live['config']!=expected and (candidate is None or live['config']!=candidate):blocked('config_changed')
        try:validate_idle(live['state'],live['config'],live['pid'],time.time())
        except ValueError:blocked('not_idle_healthy')
        return {'route_id':identity,'expected_pid':live['pid'],
                'expected_config_sha256':pending['old_config_sha256'] if pending else live['sha'],
                'payload_digest':fingerprint,'methods':[u['id'] for u in expected['upstreams']],
                'mode':expected.get('mode','failover'),'pin':expected.get('pin'),'resume':bool(pending)}

    def public(self,job):
        result=job.result or {}
        allowed={'status','counting_started_at','member_workers_restarted','member_worker_identities_preserved',
                 'interfaces_preserved','source_usage_baseline','entry_credentials_and_settings_preserved',
                 'before_idle_samples','probe_successes','probe_failures','maximum_observed_success_gap_s',
                 'recovered_existing_cutover','start_timestamp_estimated','existing_tcp_session_survival_claimed'}
        return {'id':job.id,'route_id':job.payload['route_id'],'state':job.state,'error':job.error,
                'expires_at':job.payload.get('expires_at'),'methods':job.payload.get('methods',[]),
                'mode':job.payload.get('mode'),'pin':job.payload.get('pin'),'resume':job.payload.get('resume',False),
                'controller_backup_verified':bool(result.get('controller_backup_verified')),
                'result':{k:v for k,v in result.items() if k in allowed}}

    def operation(self,session,workspace,identity):
        job=session.get(Job,identity)
        if job is None or job.kind!='accounting_migration' or job.payload.get('workspace_id')!=workspace:
            raise HTTPException(404,'migration operation not found')
        return job

    def history(self,workspace):
        # Operations live in the owner database, never in another tenant's scope.
        self.hooks.factory(workspace)
        with self.factory() as session:
            rows=session.scalars(select(Job).where(Job.kind=='accounting_migration',
                Job.payload['workspace_id'].as_string()==workspace).order_by(Job.created_at.desc()).limit(100)).all()
            return [self.public(j) for j in rows]

    def preflight(self,workspace,identity,actor):
        try:inspected=self.inspect(workspace,identity)
        except HTTPException:raise
        except Exception:blocked('preflight_unavailable')
        with self.factory() as session:
            job=Job(kind='accounting_migration',state='PREPARED',timeout_s=240,
                    payload={**inspected,'workspace_id':workspace,'actor':actor,'expires_at':time.time()+120})
            session.add(job);session.commit();return self.public(job)

    def status(self,workspace,identity):
        with self.factory() as session:return self.public(self.operation(session,workspace,identity))

    def execute(self,workspace,identity):
        lease=self.lease('admission')
        if not lease.acquire(1):blocked('busy')
        try:
            with self.factory() as session:
                job=self.operation(session,workspace,identity)
                if job.state in {'RUNNING','PASS'}:return self.public(job)
                if job.state!='PREPARED' or job.payload['expires_at']<time.time():blocked('fresh_preflight_required')
                if session.scalar(select(Job.id).where(Job.kind=='accounting_migration',Job.state=='RUNNING').limit(1)):
                    blocked('busy')
                job.state='RUNNING';job.started_at=dt.datetime.now(dt.timezone.utc);session.commit()
                public=self.public(job)
            self.kick(identity)
            return public
        finally:lease.release()

    def checkpoint(self,identity,workspace):
        folder=Path(self.hooks.registry.directory)/'accounting-migration-backups'/identity
        folder.mkdir(mode=0o700,parents=True,exist_ok=False)
        assert not folder.is_symlink()
        paths=[Path(self.hooks.store.path)]
        for factory in [self.factory,self.hooks.factory(workspace)]:
            with factory() as session:
                engine=session.get_bind();assert engine.url.drivername=='sqlite'
                paths.append(Path(engine.url.database))
        proofs=[]
        for index,path in enumerate(dict.fromkeys(paths)):
            assert path.is_file() and not path.is_symlink()
            with tempfile.TemporaryDirectory(dir=folder) as temporary:
                target=Path(temporary)/'snapshot.sqlite3'
                with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)) as source:
                    with closing(sqlite3.connect(target)) as dest:
                        source.backup(dest);assert dest.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                raw=target.read_bytes();cipher=encrypt_credentials({'database_b64':base64.b64encode(raw).decode()})
                encrypted=folder/(str(index)+'.encrypted');encrypted.write_text(cipher);encrypted.chmod(0o600)
                decoded=base64.b64decode(decrypt_credentials(encrypted.read_text())['database_b64'])
                assert hashlib.sha256(decoded).digest()==hashlib.sha256(raw).digest()
                proofs.append({'file':encrypted.name,'decrypted_sha256':hashlib.sha256(raw).hexdigest()})
        (folder/'receipt.json').write_text(json.dumps({'verified':True,'databases':proofs}))

    def kick(self,identity):
        threading.Thread(target=self.run,args=(identity,),daemon=True,name='accounting-'+identity[:8]).start()

    def run(self,identity):
        lease=self.lease(identity)
        if not lease.acquire():return
        verified=False
        try:
            with self.factory() as session:
                job=session.get(Job,identity)
                if job is None or job.state!='RUNNING':return
                payload=dict(job.payload)
            if payload['expires_at']<time.time():blocked('fresh_preflight_required')
            workspace=payload['workspace_id']
            with self.hooks.factory(workspace)() as session:
                if payload_digest(route_job(session,payload['route_id']).payload)!=payload['payload_digest']:
                    blocked('config_changed')
            def checkpoint():
                nonlocal verified
                self.checkpoint(identity,workspace);verified=True
            result=migrate(self.hooks,workspace,payload['route_id'],expected_pid=payload['expected_pid'],
                           expected_config_sha256=payload['expected_config_sha256'],
                           rescue_base='/root/tp-accounting-panel-'+identity,checkpoint=checkpoint,operation_id=identity)
            with self.factory() as session:
                job=session.get(Job,identity);job.state='PASS';job.progress=1
                job.result={**result,'controller_backup_verified':verified}
                job.finished_at=dt.datetime.now(dt.timezone.utc);session.commit()
        except Exception:
            # Never publish raw SSH output, credentials, paths or source traceback.
            with self.factory() as session:
                job=session.get(Job,identity);job.state='NEEDS_RECOVERY';job.error='migration_fresh_preflight_required'
                job.result={'controller_backup_verified':verified}
                job.finished_at=dt.datetime.now(dt.timezone.utc);session.commit()
        finally:lease.release()

    def recover(self):
        with self.factory() as session:
            identities=list(session.scalars(select(Job.id).where(Job.kind=='accounting_migration',
                Job.state.in_(['RUNNING','NEEDS_RECOVERY']))))
        for identity in identities:
            lease=self.lease(identity)
            if not lease.acquire():continue
            try:
                with self.factory() as session:
                    job=session.get(Job,identity)
                    if job.state not in {'RUNNING','NEEDS_RECOVERY'}:continue
                    receipt=None
                    try:
                        with self.hooks.factory(job.payload['workspace_id'])() as scoped:
                            route=route_job(scoped,job.payload['route_id'])
                            if route.payload.get('monthly_secret_id'):
                                receipt=route_private(scoped,route).get('accounting_operation')
                    except Exception:
                        pass  # unavailable evidence must never cause another cutover
                    if receipt and receipt.get('id')==identity and receipt['result'].get('status')=='PASS':
                        job.state='PASS';job.result=receipt['result'];job.error=None;job.progress=1
                        job.finished_at=dt.datetime.now(dt.timezone.utc)
                    elif receipt and receipt.get('id') and receipt['result'].get('status')=='PASS':
                        continued=session.get(Job,receipt['id'])
                        if (continued and continued.kind=='accounting_migration'
                                and continued.payload.get('workspace_id')==job.payload['workspace_id']
                                and continued.payload.get('route_id')==job.payload['route_id']
                                and continued.payload.get('expected_config_sha256')==job.payload.get('expected_config_sha256')):
                            job.state='SUPERSEDED';job.error=None
                            job.finished_at=dt.datetime.now(dt.timezone.utc)
                    if job.state=='RUNNING':
                        job.state='NEEDS_RECOVERY';job.error='migration_fresh_preflight_required'
                    session.commit()
            finally:lease.release()
