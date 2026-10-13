import json
from types import SimpleNamespace


def test_tun_speed_uses_marked_unprivileged_bidirectional_streams(monkeypatch):
    from orchestrator.pair_metrics import measure_tun
    from orchestrator.benchmarking import PROFILES
    from plan_executor import executor as bodies
    calls=[];records=[]
    class Remote:
        def run(self,command,**kwargs):
            calls.append(command)
            output=''
            if 'iperf3 --client' in command:
                output=json.dumps({'end':{'sum_received':{'bytes':1000000,'seconds':60,'bits_per_second':120000 if '--reverse' in command else 160000}}})
            return {'code':0,'stdout':output,'stderr':''}
    class Journal:
        def record(self,*args):records.append(args)
    monkeypatch.setattr(bodies,'install_packages',lambda *args:None)
    monkeypatch.setattr(bodies,'wait_listener',lambda *args:None)
    adapter=SimpleNamespace(remotes=[Remote(),Remote()],access=[({},{}),({'host':'192.0.2.2'}, {})],
        profile=PROFILES['DEEP'],tag='tpbench-123-1',tun_probe_user='tpb1231',tun_probe_uid=997,
        tun_route=(35017,'192.0.2.2','hdtowned'),journals=[Journal(),Journal()],extra_services=[])
    result=measure_tun(adapter)
    assert result['throughput_mbps']==.12
    assert [s['direction'] for s in result['throughput_evidence']['samples']]==['a_to_b','b_to_a']
    assert any('runuser -u tpb1231 -- iperf3 --client 192.0.2.2' in c for c in calls)
    assert any('--uid-owner 997' in c and '--set-mark 35017' in c for c in calls)
    assert any(kind=='cleanup_command' and '-D OUTPUT' in key for kind,key in records)
