import concurrent.futures
import hashlib

import pytest
from fastapi import HTTPException
from core.subscriptions import SubscriptionStore
from core.workspaces import WorkspaceRegistry
from test_mesh_api import HEADERS, panel  # noqa: F401

pytestmark=pytest.mark.unit_portable


@pytest.fixture
def trial(tmp_path):
 registry=WorkspaceRegistry(tmp_path/'customers');workspace=registry.create('Independent QA')
 now=[1800000000.0];store=SubscriptionStore(registry,mode='manual',clock=lambda:now[0])
 body={'request_id':'a'*32,'days':7,'reason':'Two-node internal QA; no payment collected'}
 return store,registry,workspace,now,body


def test_trial_is_temporary_not_money_and_replay_cannot_extend(trial):
 store,registry,w,now,body=trial
 assert store.status(w['id'])['state']=='pending_payment'
 first=store.grant_test_access(w['id'],body,actor='owner')
 state=store.status(w['id'])
 assert first['mode']=='internal_test' and not first['payment_collected']
 assert state['state']=='trial' and state['can_start_work'] and state['payment_collected'] is False
 assert state['stop_on_expiry'] and state['limits']['max_nodes']==2
 assert store.mode=='manual' and not store.manual_payments()
 now[0]+=3600
 assert store.grant_test_access(w['id'],body,actor='owner')['duplicate']
 assert store.status(w['id'])['paid_through']==first['ends_at']
 with pytest.raises(HTTPException) as error:store.grant_test_access(w['id'],{**body,'days':6},actor='owner')
 assert error.value.status_code==409
 now[0]=first['ends_at']
 assert not store.status(w['id'])['can_start_work']
 other=registry.create('Unpaid customer');assert store.status(other['id'])['state']=='pending_payment'


def test_cannot_replace_paid_existing_disabled_or_system_entitlements(trial):
 store,registry,w,_,body=trial
 store.grant_test_access(w['id'],body,actor='owner')
 with pytest.raises(HTTPException):store.grant_test_access(w['id'],{**body,'request_id':'b'*32},actor='owner')
 disabled=registry.create('Disabled');registry.update(disabled['id'],enabled=False)
 for identity in ['system',disabled['id'],'f'*32]:
  with pytest.raises(HTTPException):store.grant_test_access(identity,{**body,'request_id':'c'*32},actor='owner')
 paid=registry.create('Paid')
 with store._db() as db:
  db.execute('INSERT INTO billing_subscriptions(workspace_id,plan,revision,state,paid_through,grace_until,mode) VALUES(?,?,?,?,?,?,?)',
             (paid['id'],'pro',4,'active',1900000000,1900000000,'manual'))
 with pytest.raises(HTTPException):store.grant_test_access(paid['id'],{**body,'request_id':'d'*32},actor='owner')
 assert store.status(paid['id'])['revision']==4


def test_parallel_replay_has_one_audited_grant(trial):
 store,_,w,_,body=trial
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
  results=list(executor.map(lambda _:store.grant_test_access(w['id'],body,actor='owner'),range(4)))
 assert sum(not r['duplicate'] for r in results)==1
 assert len({r['ends_at'] for r in results})==1
 with store._db() as db:assert db.execute('SELECT COUNT(*) FROM billing_test_grants').fetchone()[0]==1


def test_http_trial_owner_scope_and_strict_body(panel,monkeypatch):
 client,_,app=panel;app.state.subscriptions.mode='manual'
 w=client.post('/api/workspaces',headers=HEADERS,json={'name':'Trial QA'}).json()
 url='/api/billing/owner/workspaces/'+w['id']+'/test-access'
 body={'request_id':'e'*32,'days':1,'reason':'Internal QA with no money collected'}
 assert client.post(url,json=body).status_code==401
 assert client.post(url,headers={'Authorization':'Bearer '+w['api_key']},json=body).status_code==403
 for role in ['VIEWER','OPERATOR']:
  monkeypatch.setenv('TP_RBAC_TOKENS',role+':'+hashlib.sha256(b'wrong-owner').hexdigest())
  assert client.post(url,headers={'Authorization':'Bearer wrong-owner'},json=body).status_code==403
 monkeypatch.setenv('TP_RBAC_TOKENS','SUPER_ADMIN:'+hashlib.sha256(b'mesh-test-owner').hexdigest())
 for change in [{'days':8},{'days':True},{'reason':''},{'reason':'        '},{'command':'no'}]:
  assert client.post(url,headers=HEADERS,json={**body,**change}).status_code==422
 response=client.post(url,headers=HEADERS,json=body)
 assert response.status_code==200,response.text
 assert response.headers['cache-control']=='no-store'
 assert response.json()['payment_collected'] is False
 assert app.state.subscriptions.status(w['id'])['can_start_work']


def test_refresh_assets_are_self_hosted_and_not_source_downloads(panel):
 client,_,_=panel
 font=client.get('/assets/tehnet-vazirmatn.woff2')
 assert font.status_code==200 and font.content[:4]==b'wOF2'
 assert font.headers['content-type'].startswith('font/woff2')
 assert client.get('/assets/theme.css').status_code==200
 assert client.get('/assets/manual_commerce.py').status_code==404
