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


def test_summary_counts_full_retained_window_and_exposes_sampling_gaps(customer):
    from core.models import OperationRecord
    from core.operations import OperationsStore
    with customer() as session:
        for n in range(240):
            session.add(OperationRecord(route_id='route1', ts=1000+n*60, kind='sample',
                document={'health':'UP', 'observed':True}))
        session.add(OperationRecord(route_id='route1', ts=16000, kind='sample',
            document={'health':'UNAVAILABLE', 'observed':False}))
        session.commit()
    store = OperationsStore(customer, clock=lambda:16060.)
    store.configure(True, 60)
    result = store.summary()['routes'][0]
    assert result['samples'] == 241  # history/export's latest200 must not truncate this report.
    assert result['health_counts'] == {'UP':240, 'DEGRADED':0, 'DOWN':0, 'UNAVAILABLE':1}
    assert result['up_sample_pct'] == pytest.approx(240/241*100)
    assert result['span_s'] == 15000
    assert result['gap_count'] == 1
    assert result['max_gap_s'] == 660
    assert result['latest_health'] == 'UNAVAILABLE'
    assert result['fresh'] is True
    assert 'SECRET_CANARY' not in json.dumps(store.support_export())


def test_summary_has_no_health_claim_without_fresh_enabled_observation(customer):
    from core.operations import OperationsStore
    now = [100.]
    store = OperationsStore(customer, clock=lambda:now[0])
    empty = store.summary()['routes'][0]
    assert empty['samples'] == 0 and empty['up_sample_pct'] is None
    assert empty['latest_health'] == 'UNAVAILABLE' and empty['fresh'] is False
    store.record('route1', observation())
    assert store.summary()['routes'][0]['fresh'] is False  # monitoring is off.
    store.configure(True, 60)
    assert store.summary()['routes'][0]['fresh'] is True
    now[0] = 231.
    stale = store.summary()['routes'][0]
    assert stale['latest_health'] == 'UP' and stale['fresh'] is False
    assert stale['last_age_s'] == 131


def test_summary_window_excludes_future_and_old_rows_and_filters_probe_values(customer):
    from core.models import OperationRecord
    from core.operations import OperationsStore
    with customer() as session:
        for ts, value in [(1, 999), (440, 10), (500, 20), (560, -5), (620, 30), (900, 999)]:
            session.add(OperationRecord(route_id='route1', ts=ts, kind='sample', document={
                'health':'UP', 'observed':True, 'password':'SECRET_CANARY',
                'probe_latency_ms':{'WIREGUARD':value, 'SECRET_CANARY':1}}))
        session.commit()
    store = OperationsStore(customer, clock=lambda:620.)
    result = store.summary(180)
    route = result['routes'][0]
    assert route['samples'] == 4
    metric = route['probe_latency_ms']['WIREGUARD']
    assert metric == {'samples':3, 'p50':20., 'p95':30., 'max':30.}
    assert 'SECRET_CANARY' not in json.dumps(result)
    assert store.support_export()['summary']['window_s'] == 86400
    with pytest.raises(ValueError):
        store.summary(8*86400)


def test_summary_treats_inconsistent_health_as_unavailable_and_is_tenant_local(customer, tmp_path):
    from core.models import OperationRecord
    from core.operations import OperationsStore
    with customer() as session:
        session.add(OperationRecord(route_id='route1', ts=100, kind='sample',
            document={'health':'UP', 'observed':False}))
        session.commit()
    assert OperationsStore(customer, clock=lambda:100.).summary()['routes'][0]['up_sample_pct'] == 0
    other = sessionmaker(bind=create_engine('sqlite:///'+str(tmp_path/'summary-other.db')))
    Base.metadata.create_all(other.kw['bind'])
    assert OperationsStore(other).summary()['routes'] == []
