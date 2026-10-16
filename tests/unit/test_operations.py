import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Base, Job

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def customer(tmp_path):
    factory = sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'tenant.db')))
    Base.metadata.create_all(factory.kw['bind'])
    with factory() as session:
        session.add(Job(id='route1', kind='mesh_route', state='COMMITTED',
            payload={'methods':['WIREGUARD'], 'password':'SECRET_CANARY', 'runtime_secret_id':'SECRET_CANARY'},
            error='SECRET_CANARY'))
        session.commit()
    return factory


def observation(up=True):
    return {'id':'route1', 'state':'COMMITTED', 'observed':up,
            'runtime':{'updated_at':100., 'healthy':{'WIREGUARD':True}, 'password':'SECRET_CANARY',
                       'active':'WIREGUARD', 'connections':3}, 'error':'SECRET_CANARY'}


def test_support_allowlist_and_unavailable_is_not_measured_down(customer):
    from core.operations import OperationsStore
    store = OperationsStore(customer, clock=lambda:100.)
    store.record('route1', observation())
    store.record('route1', observation(False))
    data = store.support_export()
    assert 'SECRET_CANARY' not in json.dumps(data)
    assert data['observations'][0]['health'] == 'UNAVAILABLE'
    assert data['observations'][0]['healthy_members'] is None
    assert data['routes'][0]['id'] == 'route1'
    assert len(data['events']) == 2
    store.record('route1', observation(False))
    assert len(store.support_export()['events']) == 2
    # Deduplication survives service reconstruction, but recovery is a new transition.
    OperationsStore(customer, clock=lambda:101.).record('route1', observation())
    assert len(store.support_export()['events']) == 3


def test_monitor_is_opt_in_and_history_is_tenant_local(customer, tmp_path):
    from core.operations import OperationsStore
    from orchestrator.operations_monitor import OperationsMonitor
    calls = []
    monitor = OperationsMonitor(observe=lambda f,r: calls.append(r) or observation(), clock=lambda:100.)
    monitor.tick(customer)
    assert calls == []
    OperationsStore(customer).configure(True, 60)
    monitor.tick(customer)
    monitor.tick(customer)
    assert calls == ['route1']
    other = sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'other.db')))
    Base.metadata.create_all(other.kw['bind'])
    assert OperationsStore(other).support_export()['observations'] == []


def test_retention_is_bounded_and_expiry_uses_only_scoped_opt_in_routes(customer):
    from core.operations import OperationsStore
    from orchestrator.operations_monitor import expire_workspace_routes
    clock = [1.]
    store = OperationsStore(customer, clock=lambda:clock[0])
    store.record('route1', observation())
    clock[0] = 8*86400.
    store.record('route1', observation())
    assert len(store.support_export()['observations']) == 1
    class Routes:
        def stop(self, factory, identity):
            with factory() as session:
                session.get(Job, identity).state = 'STOPPED'
                session.commit()
    assert expire_workspace_routes(customer, Routes())
    with customer() as session:
        assert session.get(Job, 'route1').state == 'STOPPED'


def test_malformed_remote_state_cannot_poison_monitor_or_export_secrets(customer):
    from core.operations import OperationsStore
    store=OperationsStore(customer,clock=lambda:100.)
    store.record('route1',{'state':[],'observed':True,'runtime':{'healthy':[], 'probes':[], 'active':['SECRET_CANARY'], 'mode':[]}})
    data=store.support_export()
    assert data['observations'][0]['health']=='UNAVAILABLE'
    assert 'SECRET_CANARY' not in json.dumps(data)
