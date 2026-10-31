import pytest

pytestmark=pytest.mark.unit_portable


def test_pair_adapter_owns_references_and_services_without_claiming_shared_device(monkeypatch):
    from engines.shared_kernel import deploy
    from plan_executor import executor as bodies
    records=[]
    class Journal:
        def record(self,kind,key):records.append((kind,key))
    class Remote:
        journal=Journal()
        def run(self,*args,**kwargs):return {'code':0,'stdout':''}
    calls=[]
    monkeypatch.setattr(bodies,'oneshot_service',lambda r,n,start,stop:calls.append((n,start,stop)))
    monkeypatch.setattr('orchestrator.owned_firewall.allow_protocol',lambda *args:None)
    monkeypatch.setattr('orchestrator.owned_firewall.allow_interface',lambda *args:None)
    config={'source_ip_a':'192.0.2.1','source_ip_b':'192.0.2.2','tunnel_cidr':'10.246.0.0/30',
            'tunnel_ip_a':'10.246.0.1/30','tunnel_ip_b':'10.246.0.2/30'}
    artifact=deploy('IPIP',{'id':123},{'id':1},config,Remote(),Remote(),bodies.parse_addressing(config))
    assert artifact['interface_names'][0]==artifact['interface_names'][1]
    assert artifact['interfaces_a']==artifact['interfaces_b']==[]
    assert records==[('shared_kernel_ref','123-1-IPIP')]*2
    assert len(calls)==2 and all('ip link del' not in start+stop for _,start,stop in calls)
    assert artifact['services_a']==artifact['services_b']==[bodies.unit_name(123,1)]


def test_direct_and_composite_rollback_never_delete_a_shared_interface(monkeypatch):
    from plan_executor import executor as bodies
    removed=[]
    monkeypatch.setattr(bodies,'remove_services',lambda r,n,files=None,interfaces=None:removed.append((n,interfaces)))
    class Remote:
        def run(self,*args,**kwargs):return {'code':0,'stdout':''}
    shared={'method':'IPIP','shared_kernel':True,'shared_kernel_owner':'123-1-IPIP',
        'interface_name':'tps123456789abc','systemd_unit':'netauto-123-1',
        'services_a':['netauto-123-1'],'services_b':['netauto-123-1'],'interfaces_a':[],'interfaces_b':[]}
    bodies.rollback_artifact(Remote(),Remote(),shared)
    assert all(not interfaces for _,interfaces in removed)
    owned={'services_a':['carrier-a'],'services_b':['carrier-b'],
           'interfaces_a':['owned-carrier'],'interfaces_b':['owned-carrier']}
    composed=bodies.merge_component_artifacts('IPIP_OVER_WIREGUARD',[owned,shared],shared)
    assert composed['shared_kernel'] is False
    assert composed['interfaces_a']==composed['interfaces_b']==['owned-carrier']
    bodies.rollback_artifact(Remote(),Remote(),composed)
    assert all('tps123456789abc' not in (interfaces or []) for _,interfaces in removed)
