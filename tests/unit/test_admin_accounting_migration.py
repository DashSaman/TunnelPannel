import hashlib
import time

import pytest
from test_mesh_api import HEADERS, panel  # noqa: F401

pytestmark = pytest.mark.unit_portable
BASE='/api/billing/owner/workspaces/system/accounting-migrations'


def preview_value(route):
    return {'route_id':route,'expected_pid':42,'expected_config_sha256':'a'*64,
            'methods':['GRE'],'mode':'balance','pin':None,'resume':False}


def test_owner_routes_preflight_stale_and_duplicate_execution(panel,monkeypatch):
    from core.models import Job
    client,factory,app=panel
    service=app.state.accounting_migrations
    route='a'*32
    with factory() as session:
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload={'methods':['GRE']}));session.commit()
    monkeypatch.setattr(service,'inspect',lambda workspace,identity:preview_value(identity))
    monkeypatch.setattr(service,'kick',lambda *args:None)
    assert client.get(BASE,headers=HEADERS).status_code==200
    made=client.post(BASE+'/routes/'+route+'/preflight',headers=HEADERS,json={})
    assert made.status_code==200,made.text
    ticket=made.json();assert ticket['state']=='PREPARED'
    assert 'expected_pid' not in made.text and 'config_sha256' not in made.text
    url=BASE+'/'+ticket['id']+'/execute'
    assert client.post(url,headers=HEADERS,json={'expected_pid':999}).status_code==422
    assert client.post(url,headers=HEADERS,json={}).status_code==202
    assert client.post(url,headers=HEADERS,json={}).json()['id']==ticket['id']
    with factory() as session:
        op=session.get(Job,ticket['id']);assert op.state=='RUNNING'
        op.state='PREPARED';op.payload={**op.payload,'expires_at':time.time()-1};session.commit()
    assert client.post(url,headers=HEADERS,json={}).status_code==409


def test_migration_owner_boundary_and_no_private_job_fields(panel,monkeypatch):
    client,_,app=panel
    customer=client.post('/api/workspaces',headers=HEADERS,json={'name':'Isolated'}).json()
    endpoints=[BASE,BASE+'/routes/'+'b'*32+'/preflight',BASE+'/'+'c'*32,BASE+'/'+'c'*32+'/execute']
    for role in ['OPERATOR','VIEWER']:
        monkeypatch.setenv('TP_RBAC_TOKENS',role+':'+hashlib.sha256(b'not-owner').hexdigest())
        for url in endpoints:
            call=client.get if url in [endpoints[0],endpoints[2]] else client.post
            assert call(url,headers={'Authorization':'Bearer not-owner'}).status_code==403
    for url in endpoints:
        call=client.get if url in [endpoints[0],endpoints[2]] else client.post
        assert call(url,headers={'Authorization':'Bearer '+customer['api_key']}).status_code==403
    monkeypatch.setenv('TP_RBAC_TOKENS','SUPER_ADMIN:'+hashlib.sha256(b'mesh-test-owner').hexdigest())
    assert client.get(BASE,headers=HEADERS).headers['cache-control']=='no-store'
    assert client.get(BASE+'/'+'d'*32,headers=HEADERS).status_code==404
    assert app.state.accounting_migrations


def test_interrupted_operation_needs_fresh_preflight_never_automatic_cutover(panel,monkeypatch):
    from core.models import Job
    client,factory,app=panel;service=app.state.accounting_migrations
    with factory() as session:
        session.add(Job(id='e'*32,kind='accounting_migration',state='RUNNING',payload={'workspace_id':'system','route_id':'a'*32}));session.commit()
    calls=[];monkeypatch.setattr(service,'kick',lambda *args:calls.append(args))
    service.recover()
    assert not calls
    state=client.get(BASE+'/'+'e'*32,headers=HEADERS).json()
    assert state['state']=='NEEDS_RECOVERY'
    assert client.post(BASE+'/'+'e'*32+'/execute',headers=HEADERS,json={}).status_code==409


def test_single_worker_snapshot_roundtrip_and_secret_free_report(panel,monkeypatch,tmp_path):
    from core.models import Job
    from orchestrator.remote_nodes import decrypt_credentials
    import base64
    import sqlite3
    client,factory,app=panel;service=app.state.accounting_migrations
    monkeypatch.setenv('TP_SECRET_KEY','test-only-private-installation-key')
    route='a'*32
    with factory() as session:
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload={'methods':['GRE']}));session.commit()
    from orchestrator.admin_accounting import payload_digest
    expected=preview_value(route);expected['payload_digest']=payload_digest({'methods':['GRE']})
    monkeypatch.setattr(service,'inspect',lambda *args:expected)
    monkeypatch.setattr(service,'kick',lambda *args:None)
    first=client.post(BASE+'/routes/'+route+'/preflight',headers=HEADERS,json={}).json()
    second=client.post(BASE+'/routes/'+route+'/preflight',headers=HEADERS,json={}).json()
    assert client.post(BASE+'/'+first['id']+'/execute',headers=HEADERS,json={}).status_code==202
    assert client.post(BASE+'/'+second['id']+'/execute',headers=HEADERS,json={}).status_code==409
    calls=[]
    def run(*args,**kwargs):
        kwargs['checkpoint']();calls.append(args)
        return {'status':'PASS','maximum_observed_success_gap_s':.7,'password':'never-expose','private_path':'/root/private'}
    monkeypatch.setattr('orchestrator.admin_accounting.migrate',run)
    service.checkpoint('f'*32,'system')
    service.run(first['id']);assert len(calls)==1
    result=client.get(BASE+'/'+first['id'],headers=HEADERS)
    assert result.json()['state']=='PASS' and result.json()['controller_backup_verified']
    assert 'never-expose' not in result.text and '/root/private' not in result.text
    assert client.post(BASE+'/'+first['id']+'/execute',headers=HEADERS,json={}).status_code==202
    service.run(first['id']);assert len(calls)==1
    backup=app.state.workspace_registry.directory/'accounting-migration-backups'/first['id']
    files=list(backup.glob('*.encrypted'));assert len(files)==2
    for index,path in enumerate(files):
        raw=base64.b64decode(decrypt_credentials(path.read_text())['database_b64'])
        target=tmp_path/('decrypted-'+str(index)+'.db');target.write_bytes(raw)
        with sqlite3.connect(target) as db:assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert not list(backup.rglob('snapshot.sqlite3'))


def test_lost_migration_result_stays_recoverable_and_does_not_auto_retry(panel,monkeypatch):
    from core.models import Job
    from orchestrator.admin_accounting import payload_digest
    client,factory,app=panel;service=app.state.accounting_migrations
    route='a'*32;payload={'methods':['GRE']}
    with factory() as session:
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload=payload));session.commit()
    monkeypatch.setattr(service,'inspect',lambda *args:{**preview_value(route),'payload_digest':payload_digest(payload)})
    monkeypatch.setattr(service,'kick',lambda *args:None)
    ticket=client.post(BASE+'/routes/'+route+'/preflight',headers=HEADERS,json={}).json()
    client.post(BASE+'/'+ticket['id']+'/execute',headers=HEADERS,json={})
    calls=[]
    def fail(*args,**kwargs):
        calls.append(args);raise RuntimeError('secret-token-and-private-traceback')
    monkeypatch.setattr('orchestrator.admin_accounting.migrate',fail)
    service.run(ticket['id']);service.recover();service.run(ticket['id'])
    response=client.get(BASE+'/'+ticket['id'],headers=HEADERS)
    assert response.json()['state']=='NEEDS_RECOVERY' and len(calls)==1
    assert 'secret-token' not in response.text


def test_recovery_rechecks_under_lease_and_never_overwrites_completed_ticket(panel,monkeypatch):
    from core.models import Job
    _,factory,app=panel;service=app.state.accounting_migrations
    identity='e'*32
    with factory() as session:
        session.add(Job(id=identity,kind='accounting_migration',state='RUNNING',payload={'workspace_id':'system','route_id':'a'*32}));session.commit()
    class RaceLease:
        def acquire(self):
            with factory() as session:
                job=session.get(Job,identity);job.state='PASS';job.result={'status':'PASS','probe_successes':9};session.commit()
            return True
        def release(self):pass
    monkeypatch.setattr(service,'lease',lambda *args:RaceLease())
    service.recover()
    with factory() as session:
        job=session.get(Job,identity);assert job.state=='PASS' and job.result['probe_successes']==9


def test_completed_enrollment_recovers_ticket_from_encrypted_atomic_receipt(panel,monkeypatch):
    from core.models import Job,SecretReference
    from orchestrator.remote_nodes import encrypt_credentials
    client,factory,app=panel;service=app.state.accounting_migrations
    monkeypatch.setenv('TP_SECRET_KEY','private-test-atomic-receipt-key')
    identity='e'*32;route='a'*32
    with factory() as session:
        secret=SecretReference(kind='mesh_runtime',ciphertext=encrypt_credentials({
            'config':{'monthly':{'token':'private-route-token'}},
            'accounting_operation':{'id':identity,'result':{'status':'PASS','controller_backup_verified':True,'probe_successes':7}}}))
        session.add(secret);session.flush()
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload={'runtime_secret_id':secret.id,'monthly_secret_id':'already-committed'}))
        session.add(Job(id=identity,kind='accounting_migration',state='RUNNING',payload={'workspace_id':'system','route_id':route}));session.commit()
    monkeypatch.setattr(service,'kick',lambda *args:pytest.fail('must not restart a completed cutover'))
    service.recover()
    result=client.get(BASE+'/'+identity,headers=HEADERS)
    assert result.json()['state']=='PASS' and result.json()['controller_backup_verified']
    assert result.json()['result']['probe_successes']==7 and 'private-route-token' not in result.text


def test_source_inspection_refuses_busy_or_drifted_and_already_accounted_routes(panel,monkeypatch):
    import json
    from core.models import Job,SecretReference
    from orchestrator.remote_nodes import encrypt_credentials
    client,factory,app=panel;service=app.state.accounting_migrations
    monkeypatch.setenv('TP_SECRET_KEY','private-inspection-test-only-key')
    monkeypatch.setenv('TP_MONTHLY_QUOTA_URL','https://example.invalid/quota/credits')
    route='a'*32
    config={'upstreams':[{'id':'GRE'}],'mode':'balance','pin':None}
    runtime={'directory':'/var/lib/tunnelpannel/mesh/'+route+'/gateway','service':'tpmesh-123-0-gateway','config':config}
    with factory() as session:
        secret=SecretReference(kind='mesh_runtime',ciphertext=encrypt_credentials(runtime));session.add(secret);session.flush()
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload={'runtime_secret_id':secret.id,'source':'ir','methods':['GRE']}));session.commit()
    state={'worker_pid':42,'updated_at':time.time(),'healthy':{'GRE':True},'active_connections':{'GRE':0},'order':['GRE'],'mode':'balance','pin':None}
    class Remote:
        current=config;calls=0
        def __init__(self,*args):pass
        def connect(self):return self
        def close(self):pass
        def run(self,*args,**kwargs):
            Remote.calls+=1
            return {'stdout':json.dumps({'config':Remote.current,'state':Remote.state,'pid':42,'sha':'a'*64})}
    Remote.state=state
    monkeypatch.setattr('orchestrator.admin_accounting.NodeRemote',Remote)
    monkeypatch.setattr('orchestrator.admin_accounting.node_access',lambda *args:({},{}))
    path=BASE+'/routes/'+route+'/preflight'
    assert client.post(path,headers=HEADERS,json={}).json()['state']=='PREPARED'
    Remote.state={**state,'active_connections':{'GRE':1}}
    assert client.post(path,headers=HEADERS,json={}).json()['detail']=='migration_not_idle_healthy'
    Remote.current={**config,'pin':'GRE'}
    assert client.post(path,headers=HEADERS,json={}).json()['detail']=='migration_config_changed'
    with factory() as session:
        job=session.get(Job,route);job.payload={**job.payload,'monthly_secret_id':'already'};session.commit()
    count=Remote.calls
    assert client.post(path,headers=HEADERS,json={}).json()['detail']=='migration_already_metered'
    assert Remote.calls==count


def test_finish_migration_commits_operation_receipt_with_enrollment(panel,monkeypatch):
    from core.models import Job,SecretReference
    from orchestrator.remote_nodes import encrypt_credentials,decrypt_credentials
    from orchestrator.accounting_migration import finish_migration
    _,factory,_=panel;monkeypatch.setenv('TP_SECRET_KEY','private-atomic-enrollment-test-key')
    route='a'*32;operation='e'*32;payload={};runtime={'config':{'username':'keep-private'}}
    with factory() as session:
        secret=SecretReference(kind='mesh_runtime',ciphertext=encrypt_credentials(runtime));session.add(secret);session.flush()
        payload={'runtime_secret_id':secret.id,'accounting_migration':{'phase':'pending'}}
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload=payload));session.commit()
    report={'status':'PASS','counting_started_at':time.time(),'probe_successes':7}
    finish_migration(factory,route,payload,runtime,{'monthly':{'token':'private-token'}},'candidate',report,operation)
    with factory() as session:
        job=session.get(Job,route);secret=session.get(SecretReference,job.payload['runtime_secret_id'])
        assert job.payload['monthly_secret_id']=='candidate' and 'accounting_migration' not in job.payload
        saved=decrypt_credentials(secret.ciphertext)['accounting_operation']
        assert saved['id']==operation and saved['result']['controller_backup_verified']


def test_owner_cookie_mutations_require_csrf_and_same_origin(panel,monkeypatch):
    from fastapi.testclient import TestClient
    _,_,app=panel
    service=app.state.accounting_migrations
    monkeypatch.setenv('TP_SECRET_KEY','test-cookie-owner-install-secret')
    monkeypatch.setattr(service,'inspect',lambda workspace,route:preview_value(route))
    client=TestClient(app,base_url='http://127.0.0.1',client=('127.0.0.1',12345))
    invite=client.post('/api/accounts/invitations',headers=HEADERS,json={'workspace_id':'system','email':'owner@example.test','role':'SUPER_ADMIN'}).json()
    body={'email':'owner@example.test','password':'private-long-test-password'}
    assert client.post('/auth/register',headers={'Origin':'http://127.0.0.1'},json={**body,'invitation':invite['token']}).status_code==201
    login=client.post('/auth/login',headers={'Origin':'http://127.0.0.1'},json=body).json()
    url=BASE+'/routes/'+'a'*32+'/preflight'
    assert client.post(url,json={}).status_code==403
    assert client.post(url,headers={'Origin':'https://foreign.invalid','X-CSRF-Token':login['csrf']},json={}).status_code==403
    assert client.post(url,headers={'Origin':'http://127.0.0.1','X-CSRF-Token':login['csrf']},json={}).status_code==200
