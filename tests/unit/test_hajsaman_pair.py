def test_full_hajsaman_uses_marked_xray_over_wg_over_sit():
    from engines.hajsaman_pair import full_xray_config
    config = full_xray_config(21001, 34567)
    assert config['inbounds'][0]['protocol'] == 'socks'
    assert config['outbounds'][0]['streamSettings']['sockopt']['mark'] == 34567
    assert config['outbounds'][0]['protocol'] == 'freedom'


def test_shared_sit_lower_mtu_clamps_wg_without_mutating_underlay():
    import json

    from engines.hajsaman_pair import stack_mtu
    class Remote:
        def __init__(self,mtu):self.mtu=mtu;self.commands=[]
        def run(self,command):
            self.commands.append(command)
            return {'code':0,'stdout':json.dumps([{'ifname':'owned-sit','mtu':self.mtu}])}
    a,b=Remote(1300),Remote(1480)
    assert stack_mtu((a,b),'owned-sit') == (1300,1220)
    assert all(' set ' not in c for r in (a,b) for c in r.commands)


def test_missing_sit_inventory_fails_closed_instead_of_using_hardcoded_mtu():
    import pytest

    from engines.hajsaman_pair import stack_mtu
    class Remote:
        def run(self,command):return {'code':0,'stdout':'[]'}
    with pytest.raises(RuntimeError):stack_mtu((Remote(),Remote()),'owned-sit')
