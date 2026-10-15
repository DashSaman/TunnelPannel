import pytest

pytestmark = pytest.mark.unit_portable


def test_stream_forward_and_ip_profiles_can_expose_an_honest_tcp_egress():
    from orchestrator.mesh_persistent import egress_supported
    assert all(egress_supported(method) for method in ['WIREGUARD', 'SIT_6IN4', 'GOST_GRPC',
        'FRP_TCP', 'WATERWALL_REVERSE', 'HAJSAMAN_WG'])
    assert not egress_supported('FRP_UDP')
    assert not egress_supported('SINGBOX_TUN')  # requires explicit TUN policy integration


def test_detach_closes_channels_and_releases_leases_without_destroying_warm_tunnels():
    from orchestrator.mesh_persistent import PersistentPairAdapter
    from orchestrator.benchmarking import Candidate
    class Remote:
        def close(self): self.closed = True
    class Lease:
        def release(self): self.released = True
    adapter = PersistentPairAdapter(Candidate('wireguard', 'default', 'WIREGUARD', 'VPN', 'COMPATIBLE'),
                                    [], 'NORMAL', 123456789, 1, route_id='a' * 32)
    remote, lease = Remote(), Lease()
    adapter.remotes, adapter.acquired = [remote], [lease]
    adapter.artifact = {'interface_name': 'owned-wg'}
    adapter.detach()
    assert remote.closed and lease.released
    assert adapter.artifact['interface_name'] == 'owned-wg'
