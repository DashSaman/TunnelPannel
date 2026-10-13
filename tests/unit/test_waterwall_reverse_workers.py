from plan_executor import executor as bodies


def test_reverse_link_pool_and_user_ingress_share_one_worker(monkeypatch):
    instances=[]
    for name in ('install_waterwall','allow_firewall_port','wait_listener'):
        monkeypatch.setattr(bodies,name,lambda *args,**kwargs:None)
    monkeypatch.setattr(bodies,'free_port',lambda *args,**kwargs:23017)
    monkeypatch.setattr(bodies,'adaptive_workers',lambda remote,*,multiplier=1:2*multiplier)
    def write(remote,name,document,workers):
        instances.append((document,workers)); return '/owned/test',[]
    monkeypatch.setattr(bodies,'write_waterwall_instance',write)
    bodies.deploy_waterwall_method('WATERWALL_REVERSE',{'id':123456},{'id':1,'initiator':'A'},
        {},object(),object(),{'host':'192.0.2.1'},{'host':'192.0.2.2'})
    assert [workers for _,workers in instances]==[1,1]
    assert any(n['type']=='ReverseServer' for n in instances[0][0]['nodes'])
    assert any(n['type']=='ReverseClient' for n in instances[1][0]['nodes'])
