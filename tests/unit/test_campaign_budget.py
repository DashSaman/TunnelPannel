"""Estimates and reservations must match the submitted, tenant-owned graph."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Base, Job, Node, NodeInventory
from core.workspaces import DEFAULT_LIMITS

pytestmark = pytest.mark.unit_portable


@pytest.fixture
def workspace(tmp_path):
    factory = sessionmaker(bind=create_engine('sqlite:///' + str(tmp_path/'customer.db'),
                                             connect_args={'check_same_thread':False, 'timeout':30}))
    Base.metadata.create_all(factory.kw['bind'])
    with factory() as session:
        for i in range(3):
            session.add(Node(id='node'+str(i), name='Node'+str(i), host='8.8.8.'+str(i+1),
                             host_key_fingerprint=str(i+1)*64))
            session.add(NodeInventory(node_id='node'+str(i), snapshot={'os':'linux'}))
        session.commit()
    return factory


def request(**changes):
    return SimpleNamespace(nodes=['node0','node1'], methods=['WIREGUARD'], profile='NORMAL',
        recommend_count=5, purpose='tcp_egress', **changes)


def test_hand_derived_all_pairs_units_and_honest_duration_uncertainty():
    from core.catalog import CATALOG
    from orchestrator.campaign_budget import estimate_campaign
    methods = list(CATALOG.identities)
    two = estimate_campaign(['a','b'], methods, 'NORMAL')
    assert two['candidate_units'] == 222
    assert two['route_count'] == 2 and two['method_count'] == 111
    assert two['candidate_timeout_ceiling_s'] == 133200
    assert two['profile_config']['throughput_seconds'] == 10
    assert two['traffic_bytes_estimate'] is None and two['preparation_included'] is False
    ten = estimate_campaign([str(i) for i in range(10)], methods, 'NORMAL')
    assert ten['candidate_units'] == 9990
    selected = estimate_campaign(['a','b','c'], methods, 'NORMAL',
        directions=[{'source':'a','destination':'b'}, {'source':'b','destination':'a'}])
    assert selected['candidate_units'] == 222 and selected['route_count'] == 2


@pytest.mark.parametrize('directions', [[], [{'source':'a','destination':'a'}],
    [{'source':'a','destination':'foreign'}], [{'source':'a','destination':'b'}]*2])
def test_invalid_selected_direction_is_rejected(directions):
    from orchestrator.campaign_budget import estimate_campaign
    with pytest.raises(HTTPException):
        estimate_campaign(['a','b'], ['WIREGUARD'], 'NORMAL', directions=directions)


def test_preview_does_not_create_job_and_stale_confirmation_does_not_start_work(workspace, monkeypatch):
    from orchestrator.mesh_service import CampaignService
    service = CampaignService()
    kicked = []
    monkeypatch.setattr(service, 'kick', lambda *args: kicked.append(True))
    limits = {**DEFAULT_LIMITS, 'max_daily_candidate_units':10}
    body = request()
    quote = service.preview(workspace, body, limits)
    with workspace() as session:
        assert session.query(Job).count() == 0
    body.estimate_fingerprint = quote['fingerprint']
    with workspace() as session:
        session.add(NodeInventory(node_id='node0', snapshot={'os':'linux','arch':'amd64'}))
        session.commit()
    with pytest.raises(HTTPException) as error:
        service.create(workspace, body, limits)
    assert error.value.status_code == 409
    assert not kicked
    body.estimate_fingerprint = service.preview(workspace, body, limits)['fingerprint']
    identity = service.create(workspace, body, limits)
    with workspace() as session:
        job = session.get(Job, identity)
        assert job.payload['candidate_units'] == 2
        assert job.payload['budget_day']
    assert kicked == [True]


def test_concurrent_campaigns_cannot_overspend_daily_reservations(workspace, monkeypatch):
    from orchestrator.mesh_service import CampaignService
    service = CampaignService()
    monkeypatch.setattr(service, 'kick', lambda *args: None)
    limits = {**DEFAULT_LIMITS, 'max_active_campaigns':2, 'max_daily_candidate_units':3}
    def create(_):
        try:
            return service.create(workspace, request(), limits)
        except HTTPException as error:
            return error.status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, range(2)))
    assert sum(isinstance(x,str) for x in results) == 1
    assert 429 in results
    with workspace() as session:
        assert session.query(Job).count() == 1


def test_estimate_rejects_foreign_nodes_before_admission(workspace, monkeypatch):
    from orchestrator.mesh_service import CampaignService
    service = CampaignService()
    monkeypatch.setattr(service, 'kick', lambda *args: pytest.fail('no work may start'))
    body = request()
    body.nodes = ['node0','foreign']
    with pytest.raises(HTTPException) as error:
        service.preview(workspace, body, DEFAULT_LIMITS)
    assert error.value.status_code == 400
