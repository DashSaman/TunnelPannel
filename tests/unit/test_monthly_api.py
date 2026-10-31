import time

import pytest
from test_mesh_api import HEADERS, panel  # noqa: F401

pytestmark = pytest.mark.unit_portable


def test_owner_grants_customer_pool_but_customer_cannot_edit_or_choose_another_pool(panel, monkeypatch):
    client, _, _ = panel
    monkeypatch.setenv('TP_MONTHLY_QUOTA_URL', 'https://tehnet.example/tunnels/quota/credits')
    customer = client.post('/api/workspaces', headers=HEADERS, json={'name':'Monthly customer'}).json()
    path = '/api/billing/owner/workspaces/' + customer['id'] + '/traffic'
    body = {'quota_bytes':1000,'ends_at':time.time()+30*86400,'expected_revision':0}
    assert client.put(path, headers=HEADERS, json=body).status_code == 200
    headers = {'Authorization':'Bearer '+customer['api_key']}
    status = client.get('/api/billing/traffic', headers=headers).json()
    assert status['period']['quota_bytes'] == 1000 and status['used_bytes'] == 0
    assert client.put(path, headers=headers, json=body).status_code == 403
    assert client.get(path, headers=headers).status_code == 403
    assert client.put(path, headers=HEADERS, json=body).status_code == 409
    assert client.post('/quota/credits', json={}).status_code == 401


def test_first_enable_refuses_unmetered_live_routes_without_mutating_them(panel, monkeypatch):
    from core.models import Job
    client, factory, app = panel
    monkeypatch.setenv('TP_MONTHLY_QUOTA_URL', 'https://tehnet.example/tunnels/quota/credits')
    with factory() as session:
        session.add(Job(id='keep-old',kind='mesh_route',state='COMMITTED',payload={'methods':['GRE']}))
        session.commit()
    response = client.put('/api/billing/owner/workspaces/system/traffic', headers=HEADERS,
        json={'quota_bytes':1000,'ends_at':time.time()+86400,'expected_revision':0})
    assert response.status_code == 409
    assert 'unmetered' in response.text
    assert app.state.monthly_usage.status('system')['period'] is None
    with factory() as session:
        assert session.get(Job,'keep-old').payload == {'methods':['GRE']}


def test_private_callback_binds_credit_to_route_and_workspace(panel):
    client, _, app = panel
    pool = app.state.monthly_usage
    period = pool.grant('system', 1000, time.time()+86400, expected_revision=0, actor='fixture')
    token = pool.register_route('system', 'owned-route')
    response = client.post('/quota/credits',headers={'Authorization':'Bearer '+token},
                           json={'request_id':'one','amount':500,'period_id':period['id']})
    assert response.status_code == 200
    assert response.json()['amount'] == 500
    assert client.post('/quota/credits',headers={'Authorization':'Bearer '+token},
                       json={'workspace_id':'foreign'}).status_code == 422
    assert client.get('/api/billing/traffic',headers={'Authorization':'Bearer '+token}).status_code == 401


def test_new_and_explicitly_reconciled_stopped_routes_inherit_the_pool(panel, monkeypatch):
    from core.models import Job, SecretReference
    from orchestrator.remote_nodes import decrypt_credentials
    from test_mesh_campaign import sample
    client, factory, app = panel
    monkeypatch.setenv('TP_MONTHLY_QUOTA_URL','https://tehnet.example/tunnels/quota/credits')
    monkeypatch.setenv('TP_SECRET_KEY','monthly-local-test-installation-key')
    app.state.monthly_usage.grant('system',10000,time.time()+86400,expected_revision=0,actor='fixture')
    monkeypatch.setattr('orchestrator.mesh_routes.route_samples',lambda *args:[sample('GRE')])
    monkeypatch.setattr(app.state.mesh_routes,'kick',lambda *args:None)
    with factory() as session:
        session.add(Job(id='month-campaign',kind='mesh_campaign',state='PASS',payload={
            'routes':[{'id':'pair','source':'ir','destination':'de','job_id':'child'}]}))
        session.add(Job(id='old-stopped',kind='mesh_route',state='STOPPED',payload={
            'source':'ir','destination':'de','campaign_id':'month-campaign',
            'campaign_route_id':'pair','methods':['GRE']}))
        session.commit()
    created=client.post('/api/mesh/routes',headers=HEADERS,
        json={'campaign_id':'month-campaign','route_id':'pair','methods':['GRE']})
    assert created.status_code==202,created.text
    assert client.post('/api/mesh/routes/old-stopped/reconcile',headers=HEADERS,json={}).status_code==202
    for identity in (created.json()['id'],'old-stopped'):
        with factory() as session:
            job=session.get(Job,identity)
            assert job.payload['monthly_secret_id']
            secret=decrypt_credentials(session.get(SecretReference,job.payload['monthly_secret_id']).ciphertext)
            assert secret['url']=='https://tehnet.example/tunnels/quota/credits'
            assert app.state.monthly_usage.token_workspace(secret['token'])=='system'
        public=client.get('/api/mesh/routes',headers=HEADERS).text
        assert secret['token'] not in public and 'monthly_secret_id' not in public


def test_owner_enrolled_existing_traffic_keeps_entitlement_but_disabled_and_new_routes_do_not(panel,monkeypatch):
    client,_,app=panel
    monkeypatch.setenv('TP_MONTHLY_QUOTA_URL','https://tehnet.example/tunnels/quota/credits')
    customer=client.post('/api/workspaces',headers=HEADERS,json={'name':'Preserved existing traffic'}).json()
    workspace=customer['id'];pool=app.state.monthly_usage
    period=pool.ensure_unlimited(workspace,actor='explicit-owner-migration')
    old=pool.register_route(workspace,'existing',preserve_existing=True)
    new=pool.register_route(workspace,'new')
    # Existing traffic is grandfathered; this does not activate an unpaid plan.
    monkeypatch.setattr(app.state.subscriptions,'status',lambda *args:{'can_start_work':False})
    def request(token,name):
        return client.post('/quota/credits',headers={'Authorization':'Bearer '+token},
                           json={'request_id':name,'amount':100,'period_id':period['id']})
    assert request(old,'old').status_code==200
    assert request(new,'new').status_code==403
    client.patch('/api/workspaces/'+workspace,headers=HEADERS,json={'enabled':False})
    assert request(old,'disabled').status_code==403


def test_pending_migration_fences_ordinary_policy_traffic_and_reconcile_writes(panel):
    from core.models import Job
    client,factory,_=panel
    with factory() as session:
        session.add(Job(id='pending-migration',kind='mesh_route',state='COMMITTED',payload={
            'accounting_migration':{'phase':'pending','candidate_secret_id':'private-candidate'},'methods':['GRE']}))
        session.commit()
    for suffix,method,body in [('/policy','put',{'mode':'balance'}),('/traffic','put',{'rate_mbps':2}),('/reconcile','post',{})]:
        response=getattr(client,method)('/api/mesh/routes/pending-migration'+suffix,headers=HEADERS,json=body)
        assert response.status_code==409,response.text
        assert 'migration' in response.text
