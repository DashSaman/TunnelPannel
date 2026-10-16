import hashlib
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

pytestmark=pytest.mark.unit_portable


def test_portal_assets_csp_and_scoped_customer_journey(tmp_path,monkeypatch):
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(tmp_path/'unused.db'))
    monkeypatch.setenv('TP_WORKSPACES_DIR',str(tmp_path/'customers'))
    monkeypatch.setenv('TP_RBAC_TOKENS','SUPER_ADMIN:'+hashlib.sha256(b'owner').hexdigest())
    from apps.api.main import create_app
    app=create_app(sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'owner.db'))))
    client=TestClient(app,base_url='http://127.0.0.1',client=('127.0.0.1',35000))
    page=client.get('/portal')
    assert page.status_code==200 and page.headers['content-security-policy']
    assert client.get('/assets/portal.js').status_code==200
    assert client.get('/assets/portal.css').status_code==200
    assert client.get('/assets/auth.js').status_code==200
    assert client.get('/assets/../core/accounts.py').status_code==404
    owner={'Authorization':'Bearer owner'}
    workspace=client.post('/api/workspaces',headers=owner,json={'name':'Customer'}).json()
    invitation=client.post('/api/accounts/invitations',headers=owner,
        json={'workspace_id':workspace['id'],'email':'customer@example.test'}).json()
    assert client.post('/auth/register',json={'invitation':invitation['token'],
        'email':'customer@example.test','password':'local-account-password'}).status_code==201
    login=client.post('/auth/login',json={'email':'customer@example.test','password':'local-account-password'})
    assert login.status_code==200
    csrf={'X-CSRF-Token':login.json()['csrf']}
    assert client.get('/api/billing/status').json()['workspace_id']==workspace['id']
    assert client.get('/api/operations/support').status_code==200
    assert client.get('/api/operations/audit').status_code==200
    assert client.get('/api/accounts').status_code==403
    assert client.put('/api/operations/policy',json={'enabled':True}).status_code==403
    assert client.put('/api/operations/policy',headers=csrf,json={'enabled':True}).status_code==200
    from core.models import Job
    with app.state.workspace_registry._factory(workspace['id'])() as session:
        session.add(Job(id='queued',kind='mesh_campaign',state='QUEUED',payload={'routes':[]}))
        session.commit()
    assert client.post('/api/mesh/campaigns/queued/cancel',headers=csrf).json()['state']=='CANCELLED'
    assert client.post('/auth/logout',headers=csrf).status_code==200
    assert client.get('/api/nodes').status_code==401
