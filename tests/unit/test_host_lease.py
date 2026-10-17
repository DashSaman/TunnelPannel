import pytest

pytestmark = pytest.mark.unit_portable


def test_same_physical_host_is_serialized_despite_different_customer_node_ids(tmp_path):
    from orchestrator.host_lease import HostLease
    one = HostLease({"id": "alice-node", "host": "8.8.8.8", "host_key_fingerprint": "a" * 64}, tmp_path)
    two = HostLease({"id": "bob-node", "host": "8.8.8.8", "host_key_fingerprint": "a" * 64}, tmp_path)
    assert one.acquire(timeout=0)
    try:
        assert not two.acquire(timeout=0)
    finally:
        one.release()
    assert two.acquire(timeout=.1)
    two.release()


def test_prefix_allocator_excludes_real_existing_addresses_and_routes():
    from orchestrator.host_lease import choose_prefix
    import ipaddress
    prefix = ipaddress.ip_network(choose_prefix(["10.0.0.0/8", "172.30.0.0/17"]))
    assert not prefix.overlaps(ipaddress.ip_network("10.0.0.0/8"))
    assert not prefix.overlaps(ipaddress.ip_network("172.30.0.0/17"))
    with pytest.raises(RuntimeError):
        choose_prefix(["10.0.0.0/8", "172.16.0.0/12"])


def test_ipv6_carriers_exclude_existing_routes_and_separate_pending_components():
    import ipaddress
    from orchestrator.host_lease import choose_prefix
    occupied = ['fd45:246::/49', '10.0.0.0/8']
    first = ipaddress.ip_network(choose_prefix(occupied, version=6))
    second = ipaddress.ip_network(choose_prefix([*occupied, str(first)], version=6))
    assert first.prefixlen == second.prefixlen == 64
    assert not first.overlaps(ipaddress.ip_network(occupied[0]))
    assert not first.overlaps(second)
