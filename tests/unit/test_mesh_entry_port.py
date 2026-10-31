"""A rebuilt member must not consume its own stable customer entry port."""
import json
import os
import time
from types import SimpleNamespace

import pytest
from test_mesh_api import panel  # noqa: F401
from test_host_reservations import LocalRemote

pytestmark=[pytest.mark.unit_portable,pytest.mark.skipif(os.name=='nt',reason='host reservation ownership is POSIX')]


def test_rebuild_reserves_entry_before_ssh_like_member_allocation(panel,monkeypatch,tmp_path):
    from core.models import Job,SecretReference
    from orchestrator.mesh_routes import RouteService,route_private
    from orchestrator.remote_nodes import encrypt_credentials
    from orchestrator import host_reservations as books
    from plan_executor import executor as bodies
    from test_mesh_campaign import sample
    _,factory,_=panel
    monkeypatch.setenv('TP_SECRET_KEY','entry-port-unit-test')
    # This test exercises durable entry reservations, not host inspection.
    # Keep the real allocator while giving it a known empty socket snapshot.
    monkeypatch.setattr('orchestrator.host_inventory.scan',lambda *args,**kwargs: {
        'schema':1,'complete':True,'listeners':[],'reserved_ranges':{}})
    config={'listen_host':'127.0.0.1','listen_port':22000,'username':'unit-entry','password':'unit-only-secret'}
    with factory() as session:
        secret=SecretReference(kind='mesh_runtime',ciphertext=encrypt_credentials({'config':config}))
        session.add(secret);session.flush()
        session.add(Job(id='entry-campaign',kind='mesh_campaign',state='PASS',payload={
            'routes':[{'id':'pair','job_id':'child'}]}))
        session.add(Job(id='entry-route',kind='mesh_route',state='APPLYING',payload={
            'campaign_id':'entry-campaign','campaign_route_id':'pair','source':'a','destination':'b',
            'methods':['GRE'],'listen_host':'127.0.0.1','runtime_secret_id':secret.id}))
        session.commit()
        payload=dict(session.get(Job,'entry-route').payload)
    monkeypatch.setattr('orchestrator.mesh_routes.node_access',lambda *args:({'id':'a'},{}))
    monkeypatch.setattr('orchestrator.mesh_routes.route_samples',lambda *args:[sample('GRE')])
    initialize=books.initialize
    monkeypatch.setattr(books,'initialize',lambda remote,journal,run,item:initialize(
        remote,journal,run,item,directory=tmp_path/'books'))
    class Remote(LocalRemote):
        endpoint={'id':'a'}
        def __init__(self,*args):pass
        def connect(self):return self
        def close(self):pass
        def run(self,command,**kwargs):
            if command == 'install -d -m 700 /var/lib/tunnelpannel/route-usage':
                assert kwargs.get('root') is True
                return {'code':0,'stdout':''}
            if command.startswith('cat '):return {'code':0,'stdout':json.dumps({
                'healthy':{'GRE':True},'active':'GRE','updated_at':time.time()})}
            return super().run(command,**kwargs)
    monkeypatch.setattr('orchestrator.mesh_routes.NodeRemote',Remote)
    class Lease:
        def __init__(self,*args):pass
        def acquire(self,*args):return True
        def release(self):pass
    monkeypatch.setattr('orchestrator.mesh_routes.HostLease',Lease)
    class Adapter:
        def __init__(self,*args,**kwargs):pass
        def bind(self,persist):self.persist=persist
        def configure(self):
            from orchestrator.remote_journal import RemoteJournal
            remote=Remote();journal=RemoteJournal(remote,123,1,'a',self.persist)
            books.initialize(remote,journal,123,1)
            assert bodies.free_port(remote,'tcp',22000)==22001
        def upstream(self):return {'id':'GRE','host':'127.0.0.1','port':25000}
        def detach(self):pass
        def rollback(self):pass
    monkeypatch.setattr('orchestrator.mesh_routes.PersistentPairAdapter',Adapter)
    monkeypatch.setattr('orchestrator.pair_runtime.prepare_benchmark',lambda factory:lambda request:(
        None,None,[SimpleNamespace(status='COMPATIBLE')],lambda candidate:SimpleNamespace(access=[])))
    written={}
    monkeypatch.setattr(bodies,'write_remote_text',lambda remote,path,content,mode:written.update(
        json.loads(content) if path.endswith('config.json') else {}))
    monkeypatch.setattr(bodies,'persistent_service',lambda *args:None)
    monkeypatch.setattr(bodies,'wait_listener',lambda *args:None)
    RouteService()._deploy(factory,'entry-route',payload)
    assert all(written[key]==value for key,value in config.items())
    with factory() as session:
        assert session.get(Job,'entry-route').state=='COMMITTED'
        assert route_private(session,session.get(Job,'entry-route'))['config']['listen_port']==22000
