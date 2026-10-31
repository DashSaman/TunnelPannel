import pytest

pytestmark = pytest.mark.unit_portable


@pytest.mark.parametrize('mimic', ['ssh', 'smtp', 'imap', 'postgres', 'mysql'])
def test_distinct_hedioum_handshakes_use_allocated_ports_and_matching_endpoints(mimic):
    from engines.custom_pair import hedioum_configs
    server, hub = hedioum_configs('198.51.100.7', 24567, 24568, 'test-auth', 'hdt123', False,
                                  mimics=[(mimic, 24567)])
    assert server['mimics'][0]['type'] == mimic
    assert server['mimics'][0]['port'] == 24567
    assert hub['foreign_nodes'][0]['endpoints'][0]['mimic'] == mimic
    assert server['http_decoy_port'] == -1


def test_mixed_pool_preserves_distinct_handshakes_without_default_service_ports():
    from engines.custom_pair import hedioum_configs
    endpoints = [('tls', 24567), ('ssh', 24568), ('smtp', 24569)]
    server, hub = hedioum_configs('198.51.100.7', 24567, 24570, 'test-auth', 'hdt123', False, mimics=endpoints)
    assert len(server['mimics']) == 3
    assert len(hub['foreign_nodes'][0]['endpoints']) == 3
    assert {m['port'] for m in server['mimics']} == {24567, 24568, 24569}
