from plan_executor import executor as bodies
import pytest


def test_route_based_selectors_cannot_install_default_routes(monkeypatch):
    configs = []
    stops = []
    class Remote:
        def run(self, command, **kwargs):
            return {"code": 0, "stdout": "ESTABLISHED", "stderr": ""}
    for name in ("install_strongswan", "ensure_source"):
        monkeypatch.setattr(bodies, name, lambda *args, **kw: None)
    monkeypatch.setattr(bodies, 'oneshot_service', lambda remote, name, start, stop: stops.append(stop))
    monkeypatch.setattr(bodies, "write_remote_text", lambda r, p, text, mode: configs.append(text))
    bodies.deploy_strongswan_route_based("VTI6", {"id": 123456789}, {"id": 3}, {
        "source_ip_a": "2001:db8::1", "source_ip_b": "2001:db8::2",
        "tunnel_cidr": "10.246.30.0/30", "tunnel_ip_a": "10.246.30.1/30",
        "tunnel_ip_b": "10.246.30.2/30"}, Remote(), Remote(), {}, {})
    assert all("0.0.0.0/0" not in text and "::/0" not in text for text in configs)
    assert "local_ts = 10.246.30.1/32" in configs[0]
    assert "remote_ts = 10.246.30.2/32" in configs[0]
    assert all('rm -f' not in stop for stop in stops)


def test_journal_rejects_existing_interface_before_any_delete():
    import pytest
    from orchestrator.remote_journal import RemoteJournal
    class Remote:
        def run(self, command, **kwargs):
            return {"code": 0, "stdout": "", "stderr": ""}
    journal = RemoteJournal(Remote(), 123456789, 3, "a", lambda *args: None)
    with pytest.raises(RuntimeError, match="already exists"):
        journal.observe("ip link del nvt75bcd153; ip link add nvt75bcd153 type vti")
    assert not journal.interfaces


def test_strongswan_start_uses_supported_list_conns_command():
    script = bodies.strongswan_start_script(connection_name='netauto-123-3', child_name='child-3',
        interface_create='ip -6 tunnel add nv6test mode vti6 local 2001:db8::1 remote 2001:db8::2 key 20003',
        interface_name='nv6test', address='10.246.30.1/30', peer_inner='10.246.30.2', initiate=True, vti=True)
    assert 'swanctl --list-conns --ike' not in script
    assert 'rule add priority 219 to 10.246.30.2/32 lookup main' in script


def test_peer_service_stop_does_not_trigger_a_competing_child_restart():
    config=bodies.swanctl_psk_config(connection_name='netauto-test-owned',child_name='child-owned',
        local_address='192.0.2.1',remote_address='192.0.2.2',secret='test-secret',start_action='none')
    assert 'close_action = none' in config
    assert 'dpd_action = restart' in config


def test_ipsec_interface_mtu_reserves_space_for_esp_payloads():
    script=bodies.strongswan_start_script(connection_name='owned',child_name='owned-child',
        interface_create='ip link add nvtowned type vti local 192.0.2.1 remote 192.0.2.2 key 91',
        interface_name='nvtowned',address='10.246.30.1/30',peer_inner='10.246.30.2',initiate=True,vti=True)
    assert 'ip link set nvtowned mtu 1400' in script


@pytest.mark.parametrize('method', ['IKEV2_IPSEC', 'VTI', 'VTI6'])
def test_different_warm_runs_do_not_reuse_global_xfrm_ids_or_vti_keys(monkeypatch, method):
    class Remote:
        def run(self, command, **kwargs):
            return {'code': 0, 'stdout': 'ESTABLISHED' if 'swanctl --list-sas' in command else '', 'stderr': ''}
    for name in ('install_strongswan', 'ensure_source', 'oneshot_service', 'write_remote_text'):
        monkeypatch.setattr(bodies, name, lambda *args, **kwargs: None)
    ipv6 = method == 'VTI6'
    config = {'source_ip_a': '2001:db8::1' if ipv6 else '192.0.2.1',
        'source_ip_b': '2001:db8::2' if ipv6 else '192.0.2.2', 'tunnel_cidr': '10.246.30.0/30',
        'tunnel_ip_a': '10.246.30.1/30', 'tunnel_ip_b': '10.246.30.2/30'}
    first, second = [bodies.deploy_strongswan_route_based(method, {'id': identity}, {'id': 3},
        config, Remote(), Remote(), {}, {}) for identity in [123456789, 123456790]]
    field = 'xfrm_interface_id' if method == 'IKEV2_IPSEC' else 'vti_mark'
    assert first[field] != second[field]


def test_xfrm_allocation_respects_ids_and_marks_already_present_on_either_peer():
    class Remote:
        def __init__(self, occupied=''): self.occupied, self.commands = occupied, []
        def run(self, command, **kwargs):
            self.commands.append(command)
            return {'code': 0, 'stdout': self.occupied, 'stderr': ''}
    seed = bodies.free_xfrm_identifiers([Remote(), Remote()], 123456789, 3, 'VTI')
    a, b = Remote(), Remote('if_id '+str(seed[0])+' mark '+hex(seed[1]))
    allocated = bodies.free_xfrm_identifiers([a,b], 123456789, 3, 'VTI')
    assert set(seed).isdisjoint(allocated)
    assert len(set(allocated)) == 2 and all(0 < value < 2**31 for value in allocated)
    assert all('ip xfrm state' in remote.commands and 'ip -j -d link show' in remote.commands for remote in [a,b])
