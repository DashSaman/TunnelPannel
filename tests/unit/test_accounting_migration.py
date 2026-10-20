import copy
import ast
import hashlib
import json
from types import SimpleNamespace

import pytest

from orchestrator.accounting_migration import upgraded_config, validate_idle
from test_mesh_api import panel,HEADERS  # noqa: F401

pytestmark=pytest.mark.unit_portable


def test_upgrade_preserves_every_existing_setting_and_refuses_policy_drift():
    config={'listen_host':'::1','listen_port':23000,'username':'keep','password':'keep-private-password',
            'upstreams':[{'id':'GRE','weight':.7},{'id':'IPIP','weight':2}], 'mode':'balance','pin':'IPIP',
            'max_connections':71,'custom_future':{'preserve':True}}
    before=copy.deepcopy(config)
    new=upgraded_config('a'*32,config,{'url':'https://example.invalid/quota/credits','token':'tpq_x'})
    assert config==before
    assert {k:v for k,v in new.items() if k not in {'monthly','usage_path'}}==before
    assert new['usage_path']=='/var/lib/tunnelpannel/route-usage/'+'a'*32+'.sqlite3'
    with pytest.raises(ValueError):upgraded_config('../foreign',config,{'url':'https://example.invalid/quota/credits','token':'tpq_x'})
    unsafe={**config,'usage_path':'/var/lib/foreign.sqlite3'}
    with pytest.raises(ValueError):upgraded_config('a'*32,unsafe,{'url':'https://example.invalid/quota/credits','token':'tpq_x'})
    with pytest.raises(ValueError):upgraded_config('a'*32,{**config,'monthly':{'token':'existing'}},{'url':'https://example.invalid/quota/credits','token':'tpq_x'})


def test_cutover_requires_fresh_matching_idle_worker_and_all_member_health():
    state={'worker_pid':100,'updated_at':1000,'active_connections':{'GRE':0,'IPIP':0},
           'healthy':{'GRE':True,'IPIP':True},'order':['GRE','IPIP'],'mode':'balance','pin':None}
    config={'upstreams':[{'id':'GRE'},{'id':'IPIP'}],'mode':'balance','pin':None}
    validate_idle(state,config,100,1001)
    for change in [{'worker_pid':101},{'updated_at':990},{'active_connections':{'GRE':1,'IPIP':0}},
                   {'healthy':{'GRE':False,'IPIP':True}},{'order':['IPIP','GRE']},{'mode':'failover'},{'pin':'GRE'}]:
        with pytest.raises(ValueError):validate_idle({**state,**change},config,100,1001)


@pytest.mark.parametrize('fault',['lost-response','metadata-commit','idle-timeout','rolled-back','wrong-digest'])
def test_interrupted_migration_retains_private_intent_fences_writes_and_resumes_same_token(panel,monkeypatch,fault):
    from core.models import Job,SecretReference
    from orchestrator.remote_nodes import encrypt_credentials,decrypt_credentials
    import orchestrator.accounting_migration as migration
    client,factory,app=panel
    monkeypatch.setenv('TP_SECRET_KEY','migration-test-installation-only-key')
    route='c'*32
    config={'listen_host':'127.0.0.1','listen_port':23000,'username':'old-user','password':'old-private-password',
            'upstreams':[{'id':'GRE'}],'mode':'failover','pin':None}
    raw=json.dumps(config);digest=hashlib.sha256(raw.encode()).hexdigest()
    runtime={'directory':'/var/lib/tunnelpannel/mesh/'+route+'/gateway','service':'tpmesh-123-0-gateway','config':config}
    with factory() as session:
        secret=SecretReference(kind='mesh_runtime',ciphertext=encrypt_credentials(runtime));session.add(secret);session.flush()
        session.add(Job(id=route,kind='mesh_route',state='COMMITTED',payload={'source':'source','destination':'destination','runtime_secret_id':secret.id}))
        session.commit()
    class Lease:
        def __init__(self,*args):pass
        def acquire(self,*args):return True
        def release(self):pass
    class Remote:
        current=config;calls=0;tokens=[]
        def __init__(self,*args):pass
        def connect(self):return self
        def close(self):pass
        def run(self,command,**kwargs):
            if command.startswith('cat '):return {'stdout':json.dumps(Remote.current)}
            if command.startswith('sha256sum '):return {'stdout':('0'*64 if fault=='wrong-digest' else digest)+'  config.json'}
            params=ast.literal_eval(next(line[7:] for line in command.splitlines() if line.startswith('PARAMS=')))
            Remote.calls+=1;Remote.tokens.append(params['new_config']['monthly']['token'])
            if fault=='idle-timeout' and Remote.calls==1:return {'stdout':json.dumps({'status':'FAILED_BEFORE_CUTOVER'})}
            if fault=='rolled-back' and Remote.calls==1:return {'stdout':json.dumps({'status':'FAILED_ROLLED_BACK'})}
            Remote.current=params['new_config']
            if fault=='lost-response' and Remote.calls==1:raise ConnectionError('response lost after real cutover')
            return {'stdout':json.dumps({'status':'PASS','counting_started_at':1000,'new_worker_pid':101,'recovered_existing_cutover':Remote.calls>1})}
    monkeypatch.setattr('orchestrator.remote_nodes.NodeRemote',Remote)
    monkeypatch.setattr('orchestrator.remote_nodes.node_access',lambda *args:({'host':'owned-test-source'},{}))
    monkeypatch.setattr('orchestrator.host_lease.HostLease',Lease)
    hooks=SimpleNamespace(store=app.state.monthly_usage,registry=None,factory=lambda workspace:factory,
                          lease=lambda workspace:Lease(),callback_url=lambda:'https://example.invalid/quota/credits')
    original_finish=migration.finish_migration
    if fault=='metadata-commit':
        monkeypatch.setattr(migration,'finish_migration',lambda *args:(_ for _ in ()).throw(RuntimeError('DB commit interrupted')))
    args={'expected_config_sha256':digest,'expected_pid':100,'rescue_base':'/root/tp-test-migration'}
    with pytest.raises((ConnectionError,RuntimeError,ValueError)):migration.migrate(hooks,'system',route,**args)
    if fault=='wrong-digest':
        assert hooks.store.status('system')['period'] is None and Remote.calls==0
        with factory() as session:assert 'accounting_migration' not in session.get(Job,route).payload
        return
    with factory() as session:
        job=session.get(Job,route);pending=job.payload['accounting_migration']
        candidate=decrypt_credentials(session.get(SecretReference,pending['candidate_secret_id']).ciphertext)
        assert hooks.store.preserves_existing(candidate['token'])
        assert not job.payload.get('monthly_secret_id')
    response=client.put('/api/mesh/routes/'+route+'/policy',headers=HEADERS,json={'mode':'balance'})
    assert response.status_code==409 and 'migration' in response.text
    monkeypatch.setattr(migration,'finish_migration',original_finish)
    report=migration.migrate(hooks,'system',route,**args)
    assert report['status']=='PASS' and len(set(Remote.tokens))==1
    with factory() as session:
        job=session.get(Job,route)
        assert 'accounting_migration' not in job.payload and job.payload['monthly_secret_id']==pending['candidate_secret_id']
        active=decrypt_credentials(session.get(SecretReference,job.payload['runtime_secret_id']).ciphertext)
        assert active['config']==Remote.current and active['config']['monthly']['token']==candidate['token']
