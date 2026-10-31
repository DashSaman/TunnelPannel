import json

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.models import Base, Job

pytestmark = pytest.mark.unit_portable


def spec(**changes):
    from core.service_forwards import ForwardSpec
    return ForwardSpec(**{
        'name': 'ورودی مشتری', 'route_id': 'a' * 32, 'bind_port': 25001,
        'target_host': '127.0.0.1', 'target_port': 443, **changes,
    })


def test_forward_defaults_are_loopback_and_one_explicit_target():
    from core.service_forwards import normalize_forward
    value = normalize_forward(spec().model_dump())
    assert value['bind_host'] == '127.0.0.1'
    assert value['allow_public'] is False
    assert value['source_cidrs'] == []
    assert value['target_host'] == '127.0.0.1' and value['target_port'] == 443
    # Equal source/exit loopback ports are not a loop when on distinct nodes.
    assert spec(target_port=25001).target_port == 25001


@pytest.mark.parametrize('changes', [
    {'bind_port': True}, {'bind_port': '25001'}, {'bind_port': 1023},
    {'bind_port': 65536}, {'target_port': False}, {'target_port': 0},
    {'target_port': 65536}, {'route_id': 'foreign'}, {'route_id': 'A' * 32},
    {'target_host': 'example.com'}, {'target_host': '0.0.0.0'},
    {'target_host': '224.0.0.1'}, {'target_host': '169.254.169.254'},
    {'target_host': '255.255.255.255'}, {'bind_host': '255.255.255.255'},
    {'target_host': 'fe80::1%eth0'}, {'bind_host': 'example.com'},
    {'source_cidrs': ['192.0.2.0/33']}, {'source_cidrs': '0.0.0.0/0'},
    {'source_cidrs': ['::/0'] * 33}, {'allow_public': 'yes'},
    {'workspace_id': 'b' * 32}, {'upstream': {'password': 'injected'}},
    {'name': '<script>alert(1)</script>'}, {'name': 'line\nbreak'},
    {'name': ' '}, {'name': 'x' * 81},
])
def test_forward_rejects_ambiguous_or_unbounded_input(changes):
    with pytest.raises(ValidationError):
        spec(**changes)


@pytest.mark.parametrize('host', ['0.0.0.0', '::', '192.0.2.1', '10.1.2.3'])
def test_network_bind_requires_both_public_acknowledgement_and_cidrs(host):
    with pytest.raises(ValidationError):
        spec(bind_host=host, source_cidrs=['192.0.2.0/24'])
    with pytest.raises(ValidationError):
        spec(bind_host=host, allow_public=True)
    assert spec(bind_host=host, allow_public=True, source_cidrs=['192.0.2.0/24']).bind_host == host


def test_forward_canonicalizes_mapped_v4_and_deduplicates_explicit_cidrs():
    value = spec(bind_host='::ffff:127.0.0.1', target_host='::ffff:192.0.2.5',
                 source_cidrs=['::ffff:192.0.2.8/120', '192.0.2.0/24', '2001:db8::9/64'])
    assert value.name == 'ورودی مشتری'
    assert value.bind_host == '127.0.0.1' and value.target_host == '192.0.2.5'
    assert value.source_cidrs == ['192.0.2.0/24', '2001:db8::/64']


def test_update_revision_is_strict_and_not_an_owner_or_secret_override():
    from core.service_forwards import ForwardUpdate
    value = spec().model_dump()
    with pytest.raises(ValidationError):
        ForwardUpdate(**value)
    for revision in (True, 0, '1', 2 ** 63):
        with pytest.raises(ValidationError):
            ForwardUpdate(**value, expected_revision=revision)
    assert ForwardUpdate(**value, expected_revision=1).expected_revision == 1


def test_service_lookup_and_public_projection_cannot_leak_runtime_secrets():
    from core.service_forwards import service_job, service_public
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    try:
        with factory() as session:
            job = Job(id='c' * 32, kind='mesh_service_forward', state='ACTIVE', payload={
                **spec().model_dump(), 'source': 'source-node', 'destination': 'exit-node',
                'revision': 2, 'runtime_secret_id': 'private-ref',
                'runtime': {'password': 'private-password'}, 'preflight_token': 'private-token',
            }, error='SSH failure private-password')
            session.add_all([job, Job(id='d' * 32, kind='mesh_route', state='COMMITTED', payload={})])
            session.commit()
            result = service_public(service_job(session, job.id))
            assert result['revision'] == 2 and result['state'] == 'ACTIVE'
            assert result['route_id'] == 'a' * 32
            assert result['source'] == 'source-node' and result['destination'] == 'exit-node'
            assert 'private-' not in json.dumps(result)
            assert result['error'] == 'service operation failed; inspect the private operator record'
            for identity in ('missing', 'd' * 32):
                with pytest.raises(HTTPException) as error:
                    service_job(session, identity)
                assert error.value.status_code == 404
    finally:
        engine.dispose()
