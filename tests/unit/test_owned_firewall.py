import pytest

pytestmark = pytest.mark.unit_portable


def test_owned_firewall_rules_are_peer_scoped_persistent_and_exactly_reversible(monkeypatch):
    from orchestrator.owned_firewall import allow_port, allow_interface
    records, units = [], []
    class Journal:
        marker = '123456789-3'
        def record(self, kind, key): records.append((kind, key))
    class Remote:
        journal = Journal()
        firewall_peer = '2001:db8::4'
        _tp_firewall_active = True
        def run(self, *args, **kwargs): return {'code': 1, 'stdout': ''}
    monkeypatch.setattr('plan_executor.executor.create_unit', lambda r, n, start, stop: units.append((n,start,stop)))
    remote = Remote()
    allow_port(remote, 24001, 'tcp')
    allow_interface(remote, 'ownedtun1', '10.246.1.2')
    assert len(units) == 2
    assert 'ip6tables' in units[0][1] and '-s 2001:db8::4' in units[0][1]
    assert '--dport 24001' in units[0][1]
    assert '-i ownedtun1 -s 10.246.1.2' in units[1][1]
    assert all('-D INPUT' in stop and '--comment tp-123456789-3-' in stop for _,_,stop in units)
    assert sum(kind == 'service' for kind,key in records) == 2
    assert sum(kind == 'cleanup_command' for kind,key in records) == 2
    assert all('ufw allow' not in start for _,start,_ in units)
