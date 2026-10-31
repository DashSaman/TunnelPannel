import pytest

pytestmark = pytest.mark.unit_portable


def test_reviewed_composition_matrix_has_real_overlay_and_outer_failure_domains():
    from plan_executor.executor import mesh_composite_recipe
    from orchestrator.mesh_campaign import failure_domain
    assert mesh_composite_recipe('IPIP_OVER_GOST') == ('IPIP', 'GOST', 1280)
    assert mesh_composite_recipe('WIREGUARD_OVER_SSH') == ('WIREGUARD', 'SSH', 1280)
    assert mesh_composite_recipe('VXLAN_OVER_WIREGUARD') == ('VXLAN', 'WIREGUARD', 1280)
    assert failure_domain('IPIP_OVER_WIREGUARD') == failure_domain('WIREGUARD')
    with pytest.raises(ValueError):
        mesh_composite_recipe('WIREGUARD_OVER_WIREGUARD')


def test_vxlan_port_is_free_on_both_nodes_and_reserved_before_bind():
    from plan_executor.executor import free_pair_port
    class Remote:
        def __init__(self, port): self.port=port
        def run(self, *args, **kwargs):
            return {'stdout': f'udp UNCONN 0 0 0.0.0.0:{self.port} 0.0.0.0:*\n'}
    a, b = Remote(4789), Remote(4790)
    first = free_pair_port(a, b, 'udp', 4789)
    second = free_pair_port(a, b, 'udp', 4789)
    assert first not in {4789, 4790} and second not in {4789, 4790, first}
    assert first in a.reserved_ports and first in b.reserved_ports
