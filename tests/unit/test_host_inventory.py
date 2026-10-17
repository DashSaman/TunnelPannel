"""A shared host must remain observable without exporting tunnel secrets."""
import json

import pytest

from orchestrator import host_inventory as inventory


def test_ports_include_ipv6_udp_and_container_nat_without_socket():
    listeners = inventory.parse_listeners('tcp LISTEN 0 128 [::]:21000 [::]:* users:(("nginx",pid=44,fd=5))\n'
                                          'udp UNCONN 0 0 0.0.0.0:26000 0.0.0.0:*\n')
    containers = inventory.container_ports({'8123/tcp':[{'HostIp':'::','HostPort':'21001'}],
                                            '53/udp':[{'HostIp':'0.0.0.0','HostPort':'26001'}],
                                            '80/tcp':None})
    assert {(r['proto'],r['port']) for r in listeners+containers} == {
        ('TCP',21000),('UDP',26000),('TCP',21001),('UDP',26001)}
    assert 'pid' not in json.dumps(listeners)


@pytest.mark.parametrize('mapping,complete', [('{"80/tcp":[{"HostPort":"21001","HostIp":"::"}]}',True),
                                            ('PRIVATE_INVALID_CONTAINER_OUTPUT',False)])
def test_collector_checks_container_mappings_and_fails_closed_on_unreadable_mapping(monkeypatch,mapping,complete):
    monkeypatch.setattr(inventory.shutil,'which',lambda name:name if name=='docker' else None)
    def command(args):
        if args[0]=='ss':
            return ''
        return 'abc123\n' if args[1]=='ps' else mapping
    monkeypatch.setattr(inventory,'command',command)
    report = inventory.collect(ports_only=True)
    assert report['complete'] is complete
    assert 'PRIVATE_INVALID' not in json.dumps(report)
    if complete:
        assert report['listeners'][0]['port']==21001
    else:
        assert 'docker_ports' in report['errors']


def test_both_hosts_are_inspected_before_first_reservation_write(monkeypatch,tmp_path):
    from orchestrator.benchmarking import Candidate
    from orchestrator.pair_runtime import RealPairAdapter
    monkeypatch.setenv('TP_LOCK_DIR',str(tmp_path/'leases'))
    class Remote:
        def __init__(self,endpoint,*args,**kwargs):
            self.endpoint=endpoint
        def connect(self):
            return self
        def close(self):
            pass
    monkeypatch.setattr('orchestrator.pair_runtime.NodeRemote',Remote)
    monkeypatch.setattr(inventory,'scan',lambda r: {'complete':r.endpoint['id']=='a'})
    def forbidden(*args):
        raise AssertionError('reservation written before both scans passed')
    monkeypatch.setattr('orchestrator.host_reservations.initialize',forbidden)
    access=[({'id':name,'host':name,'host_key_fingerprint':name*64},{}) for name in ['a','b']]
    adapter=RealPairAdapter(Candidate('wg','default','WIREGUARD','vpn','COMPATIBLE'),access,'QUICK',123456789,7)
    try:
        with pytest.raises(RuntimeError,match='incomplete'):
            adapter.configure()
        assert not adapter.journals and len(adapter.remotes)==2
    finally:
        adapter.rollback()


def test_inventory_command_failure_is_not_an_empty_safe_host(monkeypatch):
    def failed(*args, **kwargs):
        raise OSError('sensitive stderr')
    monkeypatch.setattr(inventory, 'command', failed)
    report = inventory.collect(ports_only=True)
    assert not report['complete'] and report['errors']
    assert 'sensitive' not in json.dumps(report)
    with pytest.raises(RuntimeError, match='incomplete'):
        inventory.require_safe(report, 'WIREGUARD')


@pytest.mark.parametrize('method', ['IKEV2_IPSEC','VTI','VTI6','L2TP_IPSEC'])
def test_existing_ipsec_daemon_or_policy_blocks_global_daemon_changes(method):
    report = {'complete':True,'listeners':[], 'services':['strongswan.service'],
              'processes':[], 'xfrm_policy_count':2, 'ip_forward':'1'}
    with pytest.raises(RuntimeError, match='IPsec'):
        inventory.require_safe(report, method)
    inventory.require_safe(report, 'WIREGUARD')


def test_reserved_ranges_validated_and_fixed_protocol_port_blocked():
    report = {'complete':True,'listeners':[{'proto':'UDP','port':1701}],
              'services':[], 'processes':[], 'xfrm_policy_count':0, 'ip_forward':'0'}
    with pytest.raises(RuntimeError, match='1701'):
        inventory.require_safe(report, 'L2TP_IPSEC')
    with pytest.raises(RuntimeError, match='forwarding'):
        inventory.require_safe(report, 'HAJSAMAN_TCP')
    assert inventory.validate_reservations({'tcp':[[21000,21009]],'udp':[26000]}) == {
        'TCP':[[21000,21009]], 'UDP':[[26000,26000]]}
    for invalid in [{'tcp':[[10,70000]]},{'tcp':[[9,8]]},{'tcp':['22']},{'wrong':[12]}]:
        with pytest.raises(ValueError):
            inventory.validate_reservations(invalid)


def test_tunnel_detection_is_evidence_based_and_has_no_private_config():
    links = [{'ifname':'wg-existing','linkinfo':{'info_kind':'wireguard','info_data':{'secret':'omit'}}},
             {'ifname':'eth0','linkinfo':{}}, {'ifname':'tun9','linkinfo':{'info_kind':'tun'}}]
    tunnels = inventory.tunnel_links(links)
    assert tunnels == [{'name':'wg-existing','kind':'wireguard'}, {'name':'tun9','kind':'tun'}]
    assert 'secret' not in json.dumps(tunnels)


def test_xfrm_policy_count_works_when_iproute_does_not_support_json():
    # Ubuntu 24.04 ip -j xfrm policy still emits plain text, not JSON.
    assert inventory.policy_count('src 10.0.0.1/32 dst 10.0.0.2/32\n dir out\n'
                                  'src ::/0 dst ::/0\n socket in priority 0\n') == 2
    assert inventory.policy_count('') == 0
    with pytest.raises(ValueError):
        inventory.policy_count('unrecognized output')


def test_port_manager_refuses_missing_scan_and_respects_operator_ranges(tmp_path, monkeypatch):
    from deploy.engine.mtf import portmgr
    monkeypatch.setattr(portmgr,'ALLOC_FILE',str(tmp_path/'alloc.json'))
    assert portmgr.free_port({'sides':{}},'tcp',['absent']) == 0
    assert portmgr.free_port({'sides':{'a':{'listeners':[], 'err':'scan failed'}}},'tcp',['a']) == 0
    report = {'sides':{'a':{'listeners':[{'proto':'TCP','port':21010}],
                           'reserved_ranges':{'TCP':[[21000,21009]]}}}}
    assert portmgr.free_port(report,'tcp',['a']) == 21011
