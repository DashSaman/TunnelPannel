import json
import pytest

pytestmark = pytest.mark.unit_portable


class Remote:
    def run(self, command, **kwargs):
        return {'stdout': '[]' if ' -j ' in command else '', 'code': 0}


def test_stopped_pair_ports_are_excluded_and_new_choice_reserved_on_both_hosts():
    from plan_executor.executor import free_pair_port
    a, b = Remote(), Remote()
    a.reserved_ports, b.reserved_ports = {22000}, {22001}
    chosen = free_pair_port(a, b, 'tcp', 22000)
    assert chosen not in {22000, 22001}
    assert chosen in a.reserved_ports and chosen in b.reserved_ports


def test_stopped_prefixes_are_excluded_and_new_choice_reserved_on_both_hosts(monkeypatch):
    from orchestrator.host_lease import unused_prefix
    monkeypatch.setattr('orchestrator.host_lease.secrets.randbelow', lambda n: 0)
    a, b = Remote(), Remote()
    a.reserved_prefixes, b.reserved_prefixes = {'10.246.0.0/30'}, {'10.246.0.4/30'}
    chosen = unused_prefix([a,b])
    assert chosen == '10.246.0.8/30'
    assert chosen in a.reserved_prefixes and chosen in b.reserved_prefixes


def test_stopped_xfrm_ids_are_excluded_even_when_ip_command_returns_no_live_state():
    from plan_executor.executor import free_xfrm_identifiers
    initial = free_xfrm_identifiers([Remote(), Remote()], 123, 1, 'VTI')
    a, b = Remote(), Remote()
    b.reserved_identifiers = set(initial)
    chosen = free_xfrm_identifiers([a,b], 123, 1, 'VTI')
    assert set(chosen).isdisjoint(initial)
    assert set(chosen) <= a.reserved_identifiers & b.reserved_identifiers


@pytest.mark.parametrize('field',['ikey','okey','key'])
def test_existing_dotted_iproute_key_is_excluded_as_a_full_32_bit_identifier(field):
    import ipaddress
    from plan_executor.executor import free_xfrm_identifiers
    initial=free_xfrm_identifiers([Remote(),Remote()],123,1,'GRETAP')
    class Peer(Remote):
        def run(self,command,**kwargs):
            if command=='ip -j -d link show':
                return {'code':0,'stdout':json.dumps([{'linkinfo':{'info_data':{
                    field:str(ipaddress.IPv4Address(initial[0]))}}}])}
            return super().run(command,**kwargs)
    chosen=free_xfrm_identifiers([Remote(),Peer()],123,1,'GRETAP')
    assert set(chosen).isdisjoint(initial)


def test_ssh_tun_id_excludes_both_stopped_tap_and_live_tun_on_either_peer():
    from orchestrator.host_reservations import free_tun_id
    class Peer(Remote):
        def run(self, command, **kwargs):
            return {'code': 0, 'stdout': json.dumps([{'ifname':'tun100001'}])}
    a, b = Remote(), Peer()
    a.reserved_interfaces = {'tap100000'}
    assert free_tun_id([a,b], 100000) == 100002


def test_failed_cleanup_retains_book_until_every_owned_mutation_is_verified():
    from orchestrator.remote_journal import RemoteJournal
    class Peer:
        def __init__(self): self.commands, self.fail = [], True
        def run(self, command, **kwargs):
            self.commands.append(command)
            if command == 'owned-policy-cleanup' and self.fail: raise RuntimeError('policy remains')
            return {'code':0, 'stdout':''}
    remote = Peer()
    journal = RemoteJournal(remote, 123, 1, 'a', lambda *args:None)
    book = '/var/lib/tunnelpannel-engine-reservations/tp-123-1.json'
    journal.paths = {book, '/var/lib/tunnelpannel/bench/owned-proof'}
    journal.cleanup_commands = {'owned-policy-cleanup'}
    with pytest.raises(RuntimeError, match='policy remains'): journal.cleanup()
    assert not any(book in command for command in remote.commands)
    remote.fail = False
    journal.cleanup()
    assert remote.commands[-2:] == ['rm -f -- ' + book, 'test ! -e ' + book]
