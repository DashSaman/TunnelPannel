import pytest

pytestmark = pytest.mark.unit_portable


@pytest.mark.parametrize('method', ['FRP_TCP', 'RATHOLE_TLS', 'SSH_REMOTE_FORWARD',
    'GOST_REMOTE_TCP', 'WSTUNNEL_REVERSE', 'WATERWALL_REVERSE', 'AUTOSSH_REVERSE'])
def test_reverse_transport_still_carries_source_a_to_destination_b(method):
    from orchestrator.pair_runtime import traffic_plan
    assert traffic_plan(method) == {'initiator': 'B', 'origin_index': 1, 'listener_side': 'A'}


def test_direct_transport_carries_source_a_to_destination_b():
    from orchestrator.pair_runtime import traffic_plan
    assert traffic_plan('VLESS_REALITY') == {'initiator': 'A', 'origin_index': 1, 'listener_side': 'A'}
