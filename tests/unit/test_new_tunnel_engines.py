import pytest

pytestmark = pytest.mark.unit_portable


def test_new_engines_are_distinct_canonical_capabilities():
    from core.catalog import CATALOG
    from orchestrator.mesh_campaign import capability, failure_domain
    from orchestrator.mesh_quality import encryption
    from orchestrator.mesh_persistent import egress_supported
    for method, engine in [('BACKHAUL_TCP', 'backhaul'), ('AMNEZIAWG', 'amneziawg'), ('IP4IN6', 'ip4in6')]:
        assert CATALOG.by_legacy(method).engine == engine
        assert egress_supported(method)
    assert capability('AMNEZIAWG') == capability('IP4IN6') == 'ip'
    assert failure_domain('IP4IN6') == 'ipv6:4'
    assert encryption('BACKHAUL_TCP') == encryption('IP4IN6') == 'none'
    assert encryption('AMNEZIAWG') == 'protocol_encrypted'


def test_sdk_never_claims_unconfigured_pair_or_unowned_executor_is_live():
    from engines.adapters.canonical_pair import BackhaulAdapter
    adapter = BackhaulAdapter({'host': '192.0.2.1'})
    assert adapter.precheck()
    assert not adapter.probe().ok
    with pytest.raises(RuntimeError, match='canonical prepared pair'):
        adapter.configure()


def test_backhaul_config_disables_host_optimizations_sniffing_and_web_ui():
    import tomllib
    from engines.backhaul import pair_configs
    server, client = pair_configs('2001:db8::1', 23456, 23457, 23458, 'test-token')
    a, b = tomllib.loads(server)['server'], tomllib.loads(client)['client']
    assert a['skip_optz'] is b['skip_optz'] is True
    assert a['web_port'] == b['web_port'] == 0
    assert a['sniffer'] is b['sniffer'] is False
    assert a['ports'] == ['127.0.0.1:23457=127.0.0.1:23458']
    assert b['remote_addr'] == '[2001:db8::1]:23456'
    assert a['transport'] == b['transport'] == 'tcp'


def test_awg_real_uapi_is_not_plain_wireguard():
    from engines.amneziawg import uapi_config, PIN
    assert len(PIN) == 40
    value = uapi_config('a'*64, 'b'*64, 23456, '2001:db8::1', 23457, '10.246.1.2')
    for line in ['jc=4', 's1=16', 's2=32', 's3=16', 's4=16', 'h1=1001',
                 'h2=1002', 'h3=1003', 'h4=1004', 'allowed_ip=10.246.1.2/32',
                 'endpoint=[2001:db8::1]:23457']:
        assert line + '\n' in value
    assert '0.0.0.0/0' not in value


def test_4in6_requires_ipv6_outer_ipv4_inner_and_distinct_next_header():
    from orchestrator.shared_kernel_runtime import normalized
    from engines.shared_kernel import METHODS
    value = {'owner': '123-1-IP4IN6', 'kind': 'ip6tnl', 'local': '2001:db8::1',
             'remote': '2001:db8::2', 'address': '10.246.0.1/30', 'peer': '10.246.0.2', 'mtu': 1400}
    assert METHODS['IP4IN6'] == 'ip6tnl'
    assert normalized(value) == value
    with pytest.raises(ValueError):
        normalized({**value, 'local': '192.0.2.1'})
    with pytest.raises(ValueError):
        normalized({**value, 'address': 'fd45:246::1/64', 'peer': 'fd45:246::2'})
